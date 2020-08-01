# Mini-Dynamo
Designed and developed a real time messaging application with multicast capability following Replicated Key-Value Storage- Simplefied Amazon Dynamo for the course CSE 586: Distributed Systems offered in Spring 2020 at University at Buffalo under the prof. Steve Ko. 

## Intoduction
### Replicated Key-Value Storage

The goal is to implement amazon dynamo:

1) Partitioning 
2) Replication
3) Failure handling

The main goal is to provide both availability and linearizability at the same time. In other words, the implementation should always perform read and write operations successfully even under failures. At the same time, a read operation should always return the most recent value.

## Implementation Details
1. Membership
	- a. Just as the original Dynamo, every node can know every other node. This means that each node knows all other nodes in the system and also knows exactly which partition belongs to which node; any node can forward a request to the correct node without using a ring-based routing.

2. Request routing
	- a. Unlike Chord, each Dynamo node knows all other nodes in the system and also knows exactly which partition belongs to which node.
	- b. Under no failures, a request for a key is directly forwarded to the coordinator (i.e., the successor of the key), and the coordinator should be in charge of serving read/write operations.

3. Quorum replication
	- a. For linearizability, you can implement a quorum-based replication used by Dynamo.
	- b. Note that the original design does not provide linearizability. You need to adapt the design.
	-	c. The replication degree N should be 3. This means that given a key, the key’s coordinator as well as the 2 successor nodes in the Dynamo ring should store the key.
	- d. Both the reader quorum size R and the writer quorum size W should be 2.
	- e. The coordinator for a get/put request should always contact other two nodes and get a vote from each (i.e., an acknowledgement for a write, or a value for a read).
	- f. For write operations, all objects can be versioned in order to distinguish stale copies from the most recent copy.
	- g. For read operations, if the readers in the reader quorum have different versions of the same object, the coordinator should pick the most recent version and return it.

4. Chain replication
	- a. Another replication strategy you can implement is chain replication, which provides linearizability.
	- b. If you are interested in more details, please take a look at the following paper: http://www.cs.cornell.edu/home/rvr/papers/osdi04.pdf
	- c. In chain replication, a write operation always comes to the first partition; then it propagates to the next two partitions in sequence. The last partition returns the result of the write.
	- d. A read operation always comes to the last partition and reads the value from the last partition.

5. Failure handling
	- a. Handling failures should be done very carefully because there can be many corner cases to consider and cover.
	- b. Just as the original Dynamo, each request can be used to detect a node failure.
	- c. For this purpose, you can use a timeout for a socket read; you can pick a reasonable timeout value, e.g., 100 ms, and if a node does not respond within the timeout, you can consider it a failure.
	- d. Do not rely on socket creation or connect status to determine if a node has failed.
	- e. When a coordinator for a request fails and it does not respond to the request, its successor can be contacted next for the request.

## Testing
For testing using grader please refer the following doc: https://docs.google.com/document/d/1ww5O0ItL0KrDm3HPDLHcJQTkMDyJtdUVSKTZziVkIpk/edit

## Reference
https://cse.buffalo.edu/~stevko/courses/cse486/spring20/lectures/28-dynamo.pdf
https://aws.amazon.com/dynamodb/
