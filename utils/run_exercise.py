#!/usr/bin/env python2
import os, sys, json, subprocess, re, argparse
from time import sleep

from p4_mininet import P4Switch, P4Host
import copy
from mininet.net import Mininet
from mininet.topo import Topo
from mininet.link import TCLink
from mininet.cli import CLI
from device import Switch, Host
from collections import defaultdict
from heapq import *
import threading

from p4runtime_switch import P4RuntimeSwitch
import p4runtime_lib.simple_controller
from dijkstra import *
_ = float('inf')



def configureP4Switch(**switch_args):
    """ Helper class that is called by mininet to initialize
        the virtual P4 switches. The purpose is to ensure each
        switch's thrift server is using a unique port.
    """
    if "sw_path" in switch_args and 'grpc' in switch_args['sw_path']:
        # If grpc appears in the BMv2 switch target, we assume will start P4Runtime
        class ConfiguredP4RuntimeSwitch(P4RuntimeSwitch):
            def __init__(self, *opts, **kwargs):
                kwargs.update(switch_args)
                P4RuntimeSwitch.__init__(self, *opts, **kwargs)

            def describe(self):
                print "%s -> gRPC port: %d" % (self.name, self.grpc_port)

        return ConfiguredP4RuntimeSwitch
    else:
        class ConfiguredP4Switch(P4Switch):
            next_thrift_port = 9090
            def __init__(self, *opts, **kwargs):
                global next_thrift_port
                kwargs.update(switch_args)
                kwargs['thrift_port'] = ConfiguredP4Switch.next_thrift_port
                ConfiguredP4Switch.next_thrift_port += 1
                P4Switch.__init__(self, *opts, **kwargs)

            def describe(self):
                print "%s -> Thrift port: %d" % (self.name, self.thrift_port)

        return ConfiguredP4Switch


class ExerciseTopo(Topo):
    """ The mininet topology class for the P4 tutorial exercises.
        A custom class is used because the exercises make a few topology
        assumptions, mostly about the IP and MAC addresses.
    """
    def __init__(self, hosts, switches, links, log_dir, **opts):
        Topo.__init__(self, **opts)
        host_links = []
        switch_links = []

        self.host_lists = []
        self.switch_lists = []

        #  save 
        # switch  ports 
        # host  switch ip mac and more

        self.sw_port_mapping = {}

        # s*********
        # gen_devices()

        for link in links:
            if link['node1'][0] == 'h':
                host_links.append(link)
            else:
                switch_links.append(link)

        link_sort_key = lambda x: x['node1'] + x['node2']
        # Links must be added in a sorted order so bmv2 port numbers are predictable
        host_links.sort(key=link_sort_key)
        switch_links.sort(key=link_sort_key)

        for sw in switches:
            self.addSwitch(sw, log_file="%s/%s.log" %(log_dir, sw))

        for link in host_links:
            host_name = link['node1']
            host_sw   = link['node2']
            host_num = int(host_name[1:])
            sw_num   = int(host_sw[1:])
            host_ip = "10.0.%d.%d" % (sw_num, host_num)
            host_mac = '00:00:00:00:%02x:%02x' % (sw_num, host_num)
            # Each host IP should be /24, so all exercise traffic will use the
            # default gateway (the switch) without sending ARP requests.
            self.addHost(host_name, ip=host_ip+'/24', mac=host_mac)

            self.addLink(host_name, host_sw,
                         delay=link['latency'], bw=link['bandwidth'],
                         addr1=host_mac, addr2=host_mac)


             # ***
            portno = self.addSwitchPort(host_sw, host_name)

            id = self.hasSwitch(host_sw)
            if id == -1:
                new_switch = Switch(host_sw)
                new_switch.addLink(host_name, portno)
                self.switch_lists.append(new_switch)
            else:
                self.switch_lists[id].addLink(host_name, portno)
            new_host =  Host(host_name, host_sw, host_ip, host_mac)
            self.host_lists.append(new_host)

        for link in switch_links:
            sw_name1 = link['node1']
            sw_name2 = link['node2']
            self.addLink(sw_name1, sw_name2,
                        delay=link['latency'], bw=link['bandwidth'])
            portno = self.addSwitchPort(sw_name1, sw_name2)

            id = self.hasSwitch(sw_name1)
            if id == -1:
                new_switch = Switch(sw_name1)
                new_switch.addLink(sw_name2, portno)
                self.switch_lists.append(new_switch)
            else:
                self.switch_lists[id].addLink(sw_name2, portno)

            portno = self.addSwitchPort(sw_name2, sw_name1)
            
            id = self.hasSwitch(sw_name2)
            if id == -1:
                new_switch = Switch(sw_name2)
                new_switch.addLink(sw_name1, portno)
                self.switch_lists.append(new_switch)
            else:
                self.switch_lists[id].addLink(sw_name1, portno)

        self.printPortMapping()



    def hasSwitch(self, switchname):
        index = 0
        for item in self.switch_lists:
            if item.name == switchname:
                return index
            index = index + 1
        return -1

    def getHostList(self):
        return self.host_lists

    def getSwitchList(self):
        return self.switch_lists


    def addSwitchPort(self, sw, node2):
        if sw not in self.sw_port_mapping:
            self.sw_port_mapping[sw] = []
        portno = len(self.sw_port_mapping[sw])+1
        self.sw_port_mapping[sw].append((portno, node2))
        return portno

    def printPortMapping(self):
        print "Switch port mapping:"
        for sw in sorted(self.sw_port_mapping.keys()):
            print "%s: " % sw,
            for portno, node2 in self.sw_port_mapping[sw]:
                print "%d:%s\t" % (portno, node2),
            print


class ExerciseRunner:
    """
        Attributes:
            log_dir  : string   // directory for mininet log files
            pcap_dir : string   // directory for mininet switch pcap files
            quiet    : bool     // determines if we print logger messages

            hosts    : list<string>       // list of mininet host names
            switches : dict<string, dict> // mininet host names and their associated properties
            links    : list<dict>         // list of mininet link properties

            switch_json : string // json of the compiled p4 example
            bmv2_exe    : string // name or path of the p4 switch binary

            topo : Topo object   // The mininet topology instance
            net : Mininet object // The mininet instance

    """
    def logger(self, *items):
        if not self.quiet:
            print(' '.join(items))

    def formatLatency(self, l):
        """ Helper method for parsing link latencies from the topology json. """
        if isinstance(l, (str, unicode)):
            return l
        else:
            return str(l) + "ms"


    def __init__(self, topo_file, log_dir, pcap_dir,
                       switch_json, bmv2_exe='simple_switch', quiet=False):
        """ Initializes some attributes and reads the topology json. Does not
            actually run the exercise. Use run_exercise() for that.

            Arguments:
                topo_file : string    // A json file which describes the exercise's
                                         mininet topology.
                log_dir  : string     // Path to a directory for storing exercise logs
                pcap_dir : string     // Ditto, but for mininet switch pcap files
                switch_json : string  // Path to a compiled p4 json for bmv2
                bmv2_exe    : string  // Path to the p4 behavioral binary
                quiet : bool          // Enable/disable script debug messages
        """

        self.quiet = quiet


        self.logger('Reading topology file.')
        with open(topo_file, 'r') as f:
            topo = json.load(f)


        self.hosts = topo['hosts']
        self.switches = topo['switches']
        self.links = self.parse_links(topo['links'])

        self.host_lists = []
        self.switch_lists = []
        self.switch_graph = None
        self.switch_graph_port = None



        # Ensure all the needed directories exist and are directories
        for dir_name in [log_dir, pcap_dir]:
            if not os.path.isdir(dir_name):
                if os.path.exists(dir_name):
                    raise Exception("'%s' exists and is not a directory!" % dir_name)
                os.mkdir(dir_name)
        self.log_dir = log_dir
        self.pcap_dir = pcap_dir
        self.switch_json = switch_json
        self.bmv2_exe = bmv2_exe



    def run_exercise(self):
        """ Sets up the mininet instance, programs the switches,
            and starts the mininet CLI. This is the main method to run after
            initializing the object.
        """
        # Initialize mininet with the topology specified by the config
        self.create_network()
        self.net.start()
        sleep(1)

        # some programming that must happen after the net has started
        self.program_hosts()
        self.program_switches()

        # wait for that to finish. Not sure how to do this better
        sleep(1)

        self.menu()


    def parse_links(self, unparsed_links):
        """ Given a list of links descriptions of the form [node1, node2, latency, bandwidth]
            with the latency and bandwidth being optional, parses these descriptions
            into dictionaries and store them as self.links
        """
        links = []
        for link in unparsed_links:
            # make sure each link's endpoints are ordered alphabetically
            s, t, = link[0], link[1]
            if s > t:
                s,t = t,s

            link_dict = {'node1':s,
                        'node2':t,
                        'latency':'0ms',
                        'bandwidth':None
                        }
            if len(link) > 2:
                link_dict['latency'] = self.formatLatency(link[2])
            if len(link) > 3:
                link_dict['bandwidth'] = link[3]

            if link_dict['node1'][0] == 'h':
                assert link_dict['node2'][0] == 's', 'Hosts should be connected to switches, not ' + str(link_dict['node2'])
            links.append(link_dict)
        return links

    def print_host_switch(self):
        print "==================HOST===================="
        for item in self.host_lists:
            self.logger('Host: %s nxtSw: %s ip: %s mac: %s \n' % (item.name, item.nextSwitch, item.ipAddress, item.macAddress))


        print "==================Switches===================="
        for item in self.switch_lists:
            self.logger('Switch: %s portSum: %s' % (item.name, item.portSum))
            for it in item.ports:
                self.logger('port: %s deviceName: %s' % (it.portNum, it.deviceName))
     
    


    def gen_bit_topo(self):
        length = len(self.switch_lists) + 1
        array = [[_ for j in range(0, length)] for i in range(0, length)]
        array_port = [[_ for j in range(0, length)] for i in range(0, length)]
        
        for item in self.switch_lists:
            sw1 = int(item.name[1:])
            for it in item.ports:
                if it.deviceName[0] == 'h':
                    continue
                sw2  = int(it.deviceName[1:])
                array[sw1][sw2] = 1
                array[sw2][sw1] = 1
                array_port[sw1][sw2] = it.portNum

        self.switch_graph = array
        self.switch_graph_port = array_port


    def print_bit_graph(self):
        self.logger("================print switch_graph===================")
        # self.logger('port: %s deviceName: %s' % (it.portNum, it.deviceName))
        for item in self.switch_graph:
            for it in item:
                print it, "\t",
            print 
        self.logger("================print switch_graph_port================")
        for item in self.switch_graph_port:
            for it in item:
                print it, "\t",
            print 


    def create_network(self):
        """ Create the mininet network object, and store it as self.net.

            Side effects:
                - Mininet topology instance stored as self.topo
                - Mininet instance stored as self.net
        """
        self.logger("Building mininet topology.")

        self.topo = ExerciseTopo(self.hosts, self.switches.keys(), self.links, self.log_dir)

        switchClass = configureP4Switch(
                sw_path=self.bmv2_exe,
                json_path=self.switch_json,
                log_console=True,
                pcap_dump=self.pcap_dir)

        self.net = Mininet(topo = self.topo,
                      link = TCLink,
                      host = P4Host,
                      switch = switchClass,
                      controller = None)



        self.host_lists = copy.deepcopy(self.topo.getHostList())
        self.switch_lists = copy.deepcopy(self.topo.getSwitchList())
        self.switch_graph = None

        self.gen_bit_topo()
        self.print_host_switch()
        # sleep(10)

        self.gen_bit_topo()
        self.print_bit_graph()


    def program_switch_p4runtime(self, sw_name, sw_dict):
        """ This method will use P4Runtime to program the switch using the
            content of the runtime JSON file as input.
        """
        sw_obj = self.net.get(sw_name)
        grpc_port = sw_obj.grpc_port
        device_id = sw_obj.device_id
        runtime_json = sw_dict['runtime_json']
        self.logger('Configuring switch %s using P4Runtime with file %s' % (sw_name, runtime_json))
        with open(runtime_json, 'r') as sw_conf_file:
            outfile = '%s/%s-p4runtime-requests.txt' %(self.log_dir, sw_name)
            p4runtime_lib.simple_controller.program_switch(
                addr='127.0.0.1:%d' % grpc_port,
                device_id=device_id,
                sw_conf_file=sw_conf_file,
                workdir=os.getcwd(),
                proto_dump_fpath=outfile)

    def program_switch_cli(self, sw_name, sw_dict):
        """ This method will start up the CLI and use the contents of the
            command files as input.
        """
        cli = 'simple_switch_CLI'
        # get the port for this particular switch's thrift server
        sw_obj = self.net.get(sw_name)
        thrift_port = sw_obj.thrift_port

        cli_input_commands = sw_dict['cli_input']
        self.logger('Configuring switch %s with file %s' % (sw_name, cli_input_commands))
        with open(cli_input_commands, 'r') as fin:
            cli_outfile = '%s/%s_cli_output.log'%(self.log_dir, sw_name)
            with open(cli_outfile, 'w') as fout:
                subprocess.Popen([cli, '--thrift-port', str(thrift_port)],
                                 stdin=fin, stdout=fout)

    def program_switches(self):
        """ This method will program each switch using the BMv2 CLI and/or
            P4Runtime, depending if any command or runtime JSON files were
            provided for the switches.
        """
        for sw_name, sw_dict in self.switches.iteritems():
            if 'cli_input' in sw_dict:
                self.program_switch_cli(sw_name, sw_dict)
            if 'runtime_json' in sw_dict:
                self.program_switch_p4runtime(sw_name, sw_dict)

    def program_hosts(self):
        """ Adds static ARP entries and default routes to each mininet host.

            Assumes:
                - A mininet instance is stored as self.net and self.net.start() has
                  been called.
        """
        for host_name in self.topo.hosts():
            h = self.net.get(host_name)
            h_iface = h.intfs.values()[0]
            link = h_iface.link

            sw_iface = link.intf1 if link.intf1 != h_iface else link.intf2
            # phony IP to lie to the host about
            host_id = int(host_name[1:])
            sw_ip = '10.0.%d.254' % host_id

            # Ensure each host's interface name is unique, or else
            # mininet cannot shutdown gracefully
            h.defaultIntf().rename('%s-eth0' % host_name)
            # static arp entries and default routes
            h.cmd('arp -i %s -s %s %s' % (h_iface.name, sw_ip, sw_iface.mac))
            h.cmd('ethtool --offload %s rx off tx off' % h_iface.name)
            h.cmd('ip route add %s dev %s' % (sw_ip, h_iface.name))
            h.setDefaultRoute("via %s" % sw_ip)


    def do_net_cli(self):
        """ Starts up the mininet CLI and prints some helpful output.

            Assumes:
                - A mininet instance is stored as self.net and self.net.start() has
                  been called.
        """
        for s in self.net.switches:
            s.describe()
        for h in self.net.hosts:
            h.describe()
        self.logger("Starting mininet CLI")
        # Generate a message that will be printed by the Mininet CLI to make
        # interacting with the simple switch a little easier.
        print('')
        print('======================================================================')
        print('Welcome to the BMV2 Mininet CLI!')
        print('======================================================================')
        print('Your P4 program is installed into the BMV2 software switch')
        print('and your initial runtime configuration is loaded. You can interact')
        print('with the network using the mininet CLI below.')
        print('')
        if self.switch_json:
            print('To inspect or change the switch configuration, connect to')
            print('its CLI from your host operating system using this command:')
            print('  simple_switch_CLI --thrift-port <switch thrift port>')
            print('')
        print('To view a switch log, run this command from your host OS:')
        print('  tail -f %s/<switchname>.log' %  self.log_dir)
        print('')
        print('To view the switch output pcap, check the pcap files in %s:' % self.pcap_dir)
        print(' for example run:  sudo tcpdump -xxx -r s1-eth1.pcap')
        print('')
        if 'grpc' in self.bmv2_exe:
            print('To view the P4Runtime requests sent to the switch, check the')
            print('corresponding txt file in %s:' % self.log_dir)
            print(' for example run:  cat %s/s1-p4runtime-requests.txt' % self.log_dir)
            print('')

        CLI(self.net)

  
    def get_host_from_list(self, host_name):
        for item in self.host_lists:
            if item.name == host_name:
                return item

        print "No Such host: " + host_name
        return None

    def get_switch_from_list(self, switch_name):
        for item in self.switch_lists:
            if item.name == switch_name:
                return item

        print "No Such Switch: " + switch_name
        return None
     
    def get_port_from_route(self, route_lists):
        ports = ""
        for index in range(0, len(route_lists)-1):
            ports += str(self.switch_graph_port[route_lists[index]][route_lists[index+1]])
        # print ports
        return ports
    
    def find_route(self, source_name, dest_name, mid_switch):
        source_host = self.get_host_from_list(source_name)
        dest_host =  self.get_host_from_list(dest_name)

        source_switch_name = source_host.nextSwitch
        dest_switch_name = dest_host.nextSwitch


        if mid_switch is None:
            # self.switch_graph_port = None
            edges = []
            for i in range(len(self.switch_graph)):
                for j in range(len(self.switch_graph[0])):
                    if i!=j and self.switch_graph[i][j]!=_:
                        edges.append((i,j, self.switch_graph[i][j]))
            
            length, Shortest_path = dijkstra(edges, int(source_switch_name[1:]), int(dest_switch_name[1:]))
            
            # print( 'length = ',length )
            # print '', Shortest_path
            self.logger('Shortest_path =  %s' % (Shortest_path))

            ports = self.get_port_from_route(Shortest_path)

            dest_switch = self.get_switch_from_list(dest_switch_name)
            last_port = ""
            for item in dest_switch.ports:
                if item.deviceName == dest_name:
                    last_port = str(item.portNum)

            print last_port
            ports = ports + last_port
            return ports, None
        else:
            edges = []
            for i in range(len(self.switch_graph)):
                for j in range(len(self.switch_graph[0])):
                    if i!=j and self.switch_graph[i][j]!=_:
                        edges.append((i,j, self.switch_graph[i][j]))
            
            length, Shortest_path = dijkstra(edges, int(source_switch_name[1:]), int(mid_switch[1:]))
            
            # print( 'length = ',length )
            # print '', Shortest_path
            self.logger('Shortest_path between source and mid =  %s' % (Shortest_path))
            ports1 = self.get_port_from_route(Shortest_path)

            length, Shortest_path = dijkstra(edges, int(mid_switch[1:]), int(dest_switch_name[1:]))
            self.logger('Shortest_path between mid and dest =  %s' % (Shortest_path))
            ports2 = self.get_port_from_route(Shortest_path)

            dest_switch = self.get_switch_from_list(dest_switch_name)
            last_port = ""
            for item in dest_switch.ports:
                if item.deviceName == dest_name:
                    last_port = str(item.portNum)

            # print last_port
            ports = ports1  + ports2 + last_port
            print "len port1", len(ports1)

            if len(ports1) == 0:
                return ports, 0
            else:
                return ports, len(ports1)

    def test_find_route(self):
        source_name  = raw_input("Input Source Host: ")
        dest_name  = raw_input("Input Dest Host:")
        mid_name  = raw_input("Input Mid Host:")
        # source_name = "h1"
        # dest_name = "h2"
        self.logger('Source Host: %s Dest Host: %s' % (source_name, dest_name))
        ports_lists, agg_idx = self.find_route(source_name, dest_name, mid_name)


        self.logger('ports_lists: %s, agg_idx %d' % (ports_lists, agg_idx))


    def parse_amount_of_data(self, str):
        if str is None:
            print("The amount of data is None")
            return
        num = 0
        amount_of_per_packet = 1296
        # amount_of_per_packet = 1500
        if str[-1] == "K" or str[-1] == "k":
            num = int(str[:-1])*1024/amount_of_per_packet
            return int(num)
        if str[-1] == "M" or str[-1] == "m":
            num = int(str[:-1])*1024*1024/amount_of_per_packet
            return int(num)
        if str[-1] == "G" or str[-1] == "g":
            num = int(str[:-1])*1024*1024*1024/amount_of_per_packet
            return int(num)

    def thread_fun(self, host, cmd):
        host.cmd(cmd)

    def test_send_data(self):
        source_name  = raw_input("Input Source Host: ")
        # print type(source_name), source_name
        dest_name  = raw_input("Input Dest Host: ")

        # source_name = "h1"
        # dest_name = "h2"
        self.logger('Source Host: %s Dest Host: %s' % (source_name, dest_name))
        ports_lists, agg_idx = self.find_route(source_name, dest_name, None)
        self.logger('ports_lists: %s' % (ports_lists))

        # print "len", len(ports_lists)


        source1 = self.net.get(source_name)
        dest2 = self.net.get(dest_name)


        agg_idx  = raw_input("Input agg_idx: ")
        whether_forward  = raw_input("Input whether_forward: ")


        # agg_idx = 1
        # whether_forward = 1
        agg_idx = int(agg_idx)
        whether_forward = int(whether_forward)

        num_str = "50M"
        num = self.parse_amount_of_data(num)
        self.logger('Data Amount: %s, packets: %d' % (num_str, num))

        if agg_idx < 0 or agg_idx >= len(ports_lists):
            print "error agg_idx"
            sleep(1)
            return 
        if whether_forward is not 0 and whether_forward is not 1:
            print "error whether_forward"
            sleep(1)
            return 

        os.system("ps -ef | grep receive.py | awk '{print $2}' | xargs kill -9")
        cmd = "  python ./receive.py"
        thread = threading.Thread(target=self.thread_fun, args=(dest2, cmd))
        thread.setDaemon(False)
        thread.start()
        sleep(0.5)

        cmd_str = " python ./send.py "+ports_lists+" "+str(agg_idx)+" "+ str(whether_forward) + " " + str(num)
        source1.cmd(cmd_str)

        print('send message to host...')
        sleep(1)

        # pid = os.fork()

        # if pid == 0:

        #     dest2.cmd(' python ./receive.py')
        #     exit(1) 
        # else:
        #     sleep(0.1)
        #     # pid1 = os.fork()
        #     # if pid1 == 0:
        #     cmd_str = " python ./send.py "+ports_lists+" 1 1"
        #     source1.cmd(cmd_str)
            # else:
            #     source3.cmd(' python ./send-no-agg.py \'31\'')



    def test_baseline(self):
        
        worker_list = ["h1", "h2", "h3", "h4", "h7", "h13"]
        ps = "h24"
        # num = 80
        # num = 400
        num = 10
        self.logger('worker list: %s, ps: %s, packet: %d' % (worker_list, ps, num))

        source_host_list = []
        host_ports_list = []
        agg_idx_list = []
        whether_forward_list = []

        dest = self.net.get(ps)
        i = 0
        for item in worker_list:
            host = self.net.get(item)
            source_host_list.append(host)

            ports_list, agg_idx = self.find_route(item, ps, "s3")
            host_ports_list.append(ports_list)
            agg_idx_list.append(0)

            whether_forward_list.append(1)

        
        os.system("ps -ef | grep receive.py | awk '{print $2}' | xargs kill -9")
        sleep(1)
        cmd = " python ./receive.py" + " zzz_baseline.txt"
        print "cmd", cmd
        thread = threading.Thread(target=self.thread_fun, args=(dest, cmd))
        thread.setDaemon(False)
        thread.start()
        sleep(0.5)

        iteration = 105
        for j in range(0, iteration):
            print "iteration:", j
            threads = []
            for i  in range(0, len(source_host_list)):
                cmd_str = " python ./send.py "+ host_ports_list[i]+" "+str(agg_idx_list[i])+" "+ str(whether_forward_list[i]) + " " + str(num) + " zzz_baseline.txt"
                print "cmd", cmd_str
                thread = threading.Thread(target=self.thread_fun, args=(source_host_list[i], cmd_str))
                thread.setDaemon(False)
                threads.append(thread)
                thread.start()
            for t in threads:
                t.join()
            # sleep(10)
            sleep(4)

    
    def test_agg(self):
        
        worker_list = ["h1", "h2", "h3", "h4", "h7", "h13"]
        ps = "h24"

        # num = 10
        # num = 400

        self.logger('worker list: %s, ps: %s, packet: %d' % (worker_list, ps, num))

        source_host_list = []
        host_ports_list = []
        agg_idx_list = []
        whether_forward_list = []

        dest = self.net.get(ps)
        i = 0
        for item in worker_list:
            host = self.net.get(item)
            source_host_list.append(host)

            # ports_list, agg_idx = self.find_route(item, ps, "s6")

            ports_list, agg_idx = self.find_route(item, ps, "s1")

            host_ports_list.append(ports_list)
            agg_idx_list.append(0)

            if item == worker_list[-1]:
                whether_forward_list.append(1)
            else:
                whether_forward_list.append(0)
            i = i+1
        
        os.system("ps -ef | grep receive.py | awk '{print $2}' | xargs kill -9")
        sleep(0.5)
        cmd = " python ./receive.py"+ " zzz_agg.txt"
        print "cmd", cmd
        thread = threading.Thread(target=self.thread_fun, args=(dest, cmd))
        thread.setDaemon(False)
        thread.start()
        sleep(0.5)

        iteration = 105
        for j in range(0, iteration):
            print "iteration:", j
            threads = []
            for i  in range(0, len(source_host_list)):
                cmd_str = " python ./send.py "+ host_ports_list[i]+" "+str(agg_idx_list[i])+" "+ str(whether_forward_list[i]) + " " + str(num)+ " zzz_agg.txt"
                print "cmd", cmd_str
                thread = threading.Thread(target=self.thread_fun, args=(source_host_list[i], cmd_str))
                thread.setDaemon(False)
                threads.append(thread)
                thread.start()
            for t in threads:
                t.join()
            sleep(4)
            # sleep(10)
    

    def test_agg_new(self):
        
        worker_list = ["h1", "h2", "h3", "h4", "h7", "h13"]
        ps = "h24"

        num = 80
        # num = 400

        self.logger('worker list: %s, ps: %s, packet: %d' % (worker_list, ps, num))


        source_host_list = []
        host_ports_list = []
        agg_idx_list = []
        whether_forward_list = []

        dest = self.net.get(ps)
        i = 0
        for item in worker_list:
            host = self.net.get(item)
            source_host_list.append(host)

            # ports_list, agg_idx = self.find_route(item, ps, "s6")

            ports_list, agg_idx = self.find_route(item, ps, "s1")

            host_ports_list.append(ports_list)
            agg_idx_list.append(agg_idx)

            if item == worker_list[0]:
                whether_forward_list.append(1)
            else:
                whether_forward_list.append(0)
            i = i+1
        
        os.system("ps -ef | grep receive.py | awk '{print $2}' | xargs kill -9")
        sleep(0.5)
        cmd = " python ./receive.py"+ " zzz_agg.txt"
        print "cmd", cmd
        thread = threading.Thread(target=self.thread_fun, args=(dest, cmd))
        thread.setDaemon(False)
        thread.start()
        sleep(0.5)

        iteration = 105
        for j in range(0, iteration):
            print "iteration:", j
            threads = []
            for i  in range(0, len(source_host_list)):
                cmd_str = " python ./send.py "+ host_ports_list[i]+" "+str(agg_idx_list[i])+" "+ str(whether_forward_list[i]) + " " + str(num)+ " zzz_agg.txt"
                print "cmd", cmd_str
                thread = threading.Thread(target=self.thread_fun, args=(source_host_list[i], cmd_str))
                thread.setDaemon(False)
                threads.append(thread)
                thread.start()
            for t in threads:
                t.join()
            sleep(4)
            # sleep(10)
    
    def test_agg_different_worker(self):
        worker_lists = []
        worker_list = ["h1", "h7"]
        worker_lists.append(worker_list)
        worker_list = ["h1", "h7", "h13"]
        worker_lists.append(worker_list)
        worker_list = ["h1", "h7", "h13", "h19"]
        worker_lists.append(worker_list)
        worker_list = ["h1", "h4", "h7", "h10", "h13", "h19"]
        worker_lists.append(worker_list)
        worker_list = ["h1", "h4", "h7", "h10", "h13", "h19", "h16", "h22"]
        worker_lists.append(worker_list)
        worker_list = ["h1", "h3", "h4", "h6", "h7", "h10", "h13", "h16", "h19",  "h22"]
        worker_lists.append(worker_list)
        worker_list = ["h1", "h3", "h4", "h6", "h7", "h10", "h13", "h16", "h19", "h21", "h22"]
        worker_list = ["h1", "h3", "h4", "h6", "h7", "h10", "h13", "h16","h17", "h19", "h21", "h22"]
        worker_list = ["h1", "h3", "h4","h5", "h6", "h7", "h10", "h13", "h16", "h17", "h19", "h21", "h22"]
        worker_lists.append(worker_list)

        ps = "h24"
        num = 10
        key_idx = 0
        for worker_list in worker_lists:
        
            self.logger('id: %d worker list: %s, ps: %s, packet: %d' % (key_idx, worker_list, ps, num))

            source_host_list = []
            host_ports_list = []
            agg_idx_list = []
            whether_forward_list = []

            dest = self.net.get(ps)
            i = 0
            for item in worker_list:
                host = self.net.get(item)
                source_host_list.append(host)

                # ports_list, agg_idx = self.find_route(item, ps, "s6")

                ports_list, agg_idx = self.find_route(item, ps, "s1")

                host_ports_list.append(ports_list)
                agg_idx_list.append(agg_idx)

                if item == worker_list[-1]:
                    whether_forward_list.append(1)
                else:
                    whether_forward_list.append(0)
                i = i+1
            
            os.system("ps -ef | grep receive.py | awk '{print $2}' | xargs kill -9")
            sleep(0.5)
            cmd = " python ./receive.py"+ " zzz_agg_diff_worker.txt"
            print "cmd", cmd
            thread = threading.Thread(target=self.thread_fun, args=(dest, cmd))
            thread.setDaemon(False)
            thread.start()
            sleep(0.5)

            iteration = 40
            for j in range(0, iteration):
                print "iteration:", j
                threads = []
                for i  in range(0, len(source_host_list)):
                    cmd_str = " python ./send.py "+ host_ports_list[i]+" "+str(agg_idx_list[i])+" "+ str(whether_forward_list[i]) + " " + str(num)+ " zzz_agg_diff_worker.txt"
                    print "cmd", cmd_str
                    thread = threading.Thread(target=self.thread_fun, args=(source_host_list[i], cmd_str))
                    thread.setDaemon(False)
                    threads.append(thread)
                    thread.start()
                for t in threads:
                    t.join()
                sleep(4)
                # sleep(10)
    def test_rss(self):
        worker_list = ["h1", "h2", "h3", "h4", "h7", "h13"]
        ps = "h24"

        num = 80
        # num = 1

        self.logger('worker list: %s, ps: %s, packet: %d' % (worker_list, ps, num))

        source_host_list = []
        host_ports_list = []
        agg_idx_list = []
        whether_forward_list = []

        dest = self.net.get(ps)
        i = 0
        for item in worker_list:
            host = self.net.get(item)
            source_host_list.append(host)

            ports_list, agg_idx = self.find_route(item, ps, "s13")
            host_ports_list.append(ports_list)
            agg_idx_list.append(0)

            if item == worker_list[-1]:
                whether_forward_list.append(1)
            else:
                whether_forward_list.append(0)
            i = i+1
        
        os.system("ps -ef | grep receive.py | awk '{print $2}' | xargs kill -9")
        sleep(0.5)
        cmd = " python ./receive.py"+ " zzz_rss.txt"
        print "cmd", cmd
        thread = threading.Thread(target=self.thread_fun, args=(dest, cmd))
        thread.setDaemon(False)
        thread.start()
        sleep(0.5)

        iteration = 105
        for j in range(0, iteration):
            print "iteration:", j
            threads = []
            for i  in range(0, len(source_host_list)):
                cmd_str = " python ./send.py "+ host_ports_list[i]+" "+str(agg_idx_list[i])+" "+ str(whether_forward_list[i]) + " " + str(num)+ " zzz_rss.txt"
                print "cmd", cmd_str
                thread = threading.Thread(target=self.thread_fun, args=(source_host_list[i], cmd_str))
                thread.setDaemon(False)
                threads.append(thread)
                thread.start()
            for t in threads:
                t.join()
            sleep(4)
            # sleep(8)

    def test_rss_new(self):
        worker_list = ["h1", "h2", "h3", "h4", "h7", "h13"]
        ps = "h24"

        num = 80
        # num = 1

        self.logger('worker list: %s, ps: %s, packet: %d' % (worker_list, ps, num))


        source_host_list = []
        host_ports_list = []
        agg_idx_list = []
        whether_forward_list = []

        dest = self.net.get(ps)

        for item in worker_list[0:3]:
            host = self.net.get(item)
            source_host_list.append(host)

            ports_list, agg_idx = self.find_route(item, ps, "s13")
            host_ports_list.append(ports_list)
            agg_idx_list.append(agg_idx)

            if item == worker_list[2]:
                whether_forward_list.append(1)
            else:
                whether_forward_list.append(0)
  
        
        for item in worker_list[3:6]:
            host = self.net.get(item)
            source_host_list.append(host)
            ports_list, agg_idx = self.find_route(item, ps, None)
            host_ports_list.append(ports_list)
            agg_idx_list.append(0)
            whether_forward_list.append(1)


        # self.logger('worker list: %s, ps: %s, packet: %d' % (worker_list, ps, num))


        os.system("ps -ef | grep receive.py | awk '{print $2}' | xargs kill -9")
        sleep(0.5)
        cmd = " python ./receive.py"+ " zzz_rss_new.txt"
        print "cmd", cmd
        thread = threading.Thread(target=self.thread_fun, args=(dest, cmd))
        thread.setDaemon(False)
        thread.start()
        sleep(0.5)

        iteration = 105
        for j in range(0, iteration):
            print "iteration:", j
            threads = []
            for i  in range(0, len(source_host_list)):
                cmd_str = " python ./send.py "+ host_ports_list[i]+" "+str(agg_idx_list[i])+" "+ str(whether_forward_list[i]) + " " + str(num)+ " zzz_rss_new.txt"
                print "cmd", cmd_str
                thread = threading.Thread(target=self.thread_fun, args=(source_host_list[i], cmd_str))
                thread.setDaemon(False)
                threads.append(thread)
                thread.start()
            for t in threads:
                t.join()
            # sleep(4)
            sleep(4)


    def test_all(self):
        self.test_agg()
        self.test_rss_new()
        self.test_rss()
        self.test_baseline()

    def menu(self):
        while True:
            # subprocess.call("clear", shell=True)
            print('======================================================================')
            print('Welcome to the BMV2 Mininet')
            print('======================================================================')
            print('Input 0: exit=========================================================')
            print('Input 1: goto CLI=====================================================')
            print('Input 2: goto Test_find_route=========================================')
            print('Input 3: goto Test_send_data==========================================')
            print('Input 4: goto BaseLine================================================')
            print('Input 5: goto AGG=====================================================')
            print('Input 6: goto RSS=====================================================')
            print('Input 7: goto test ALL================================================')
            print('Input 9: goto test agg-new============================================')
            print('Input 10: goto test agg-diff-worker===================================')
            key  = raw_input("input key: ")
            # print type(key), key
            key = int(key)

            sys.stdout.flush()
            if key == 0:
                # stop right after the CLI is exited
                self.net.stop()
                clear_all()
                break
            elif key == 1:
                self.do_net_cli()
            elif key == 2:
                self.test_find_route()
            elif key == 3:
                self.test_send_data()
            elif key == 4:
                self.test_baseline()
            elif key == 5:
                self.test_agg()
            elif key == 6:       
                self.test_rss()
            elif key == 7:
                self.test_all()
            elif key == 8:
                self.test_rss_new()
            elif key == 9:
                self.test_agg_new()
            elif key == 10:
                self.test_agg_different_worker()
            else:
                sys.stdout.flush()
                print('error input')
                continue
                


def clear_all():
    os.system('sudo mn -c')
    os.system('sudo rm -f *.pcap')
    os.system('sudo rm -rf build logs pcaps')
def get_args():
    cwd = os.getcwd()
    default_logs = os.path.join(cwd, 'logs')
    default_pcaps = os.path.join(cwd, 'pcaps')
    parser = argparse.ArgumentParser()
    parser.add_argument('-q', '--quiet', help='Suppress log messages.',
                        action='store_true', required=False, default=False)
    parser.add_argument('-t', '--topo', help='Path to topology json',
                        type=str, required=False, default='./topology.json')
    parser.add_argument('-l', '--log-dir', type=str, required=False, default=default_logs)
    parser.add_argument('-p', '--pcap-dir', type=str, required=False, default=default_pcaps)
    parser.add_argument('-j', '--switch_json', type=str, required=False)
    parser.add_argument('-b', '--behavioral-exe', help='Path to behavioral executable',
                                type=str, required=False, default='simple_switch')
    return parser.parse_args()


        
if __name__ == '__main__':
    # from mininet.log import setLogLevel
    # setLogLevel("info")

    args = get_args()
    exercise = ExerciseRunner(args.topo, args.log_dir, args.pcap_dir,
                              args.switch_json, args.behavioral_exe, args.quiet)

    exercise.run_exercise()

