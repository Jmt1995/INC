from collections import defaultdict
from heapq import *

def dijkstra_raw(edges, from_node, to_node):
	g = defaultdict(list)
	for l,r,c in edges:
		g[l].append((c,r))
	q, seen = [(0,from_node,())], set()
	while q:
		(cost,v1,path) = heappop(q)
		if v1 not in seen:
			seen.add(v1)
			path = (v1, path)
			if v1 == to_node:
				return cost,path
			for c, v2 in g.get(v1, ()):
				if v2 not in seen:
					heappush(q, (cost+c, v2, path))
	return float("inf"),[]

def dijkstra(edges, from_node, to_node):
	len_shortest_path = -1
	ret_path=[]
	length,path_queue = dijkstra_raw(edges, from_node, to_node)
	if len(path_queue)>0:
		len_shortest_path = length		## 1. Get the length firstly;
		## 2. Decompose the path_queue, to get the passing nodes in the shortest path.
		left = path_queue[0]
		ret_path.append(left)		## 2.1 Record the destination node firstly;
		right = path_queue[1]
		while len(right)>0:
			left = right[0]
			ret_path.append(left)	## 2.2 Record other nodes, till the source-node.
			right = right[1]
		ret_path.reverse()	## 3. Reverse the list finally, to make it be normal sequence.
	return len_shortest_path,ret_path

if __name__ == '__main__':
	N = float('inf')
	M_topo = [
		[N,  N, N, N],
		[N, N, 1, 1 ],
		[N, 1, N, 1],
		[N, 1, 1, N]
	]

	edges = []
	for i in range(len(M_topo)):
		for j in range(len(M_topo[0])):
			if i!=j and M_topo[i][j]!=N:
				edges.append((i,j,M_topo[i][j]))### (i,j) is a link; M_topo[i][j] here is 1, the length of link (i,j)

	length, Shortest_path = dijkstra(edges, 1, 3)
	# vertex = ['A', 'B', 'C', 'D']
	print( 'length = ',length )
	print( 'length = ',Shortest_path )

