# Oblivious Transfer

This module implements the Oblivous Transfer with the following
algorithms:

 - RSA: simple RSA encryption based OT. Each transfer requires one RSA
   operation.
 - Chou Orlandi OT: Diffie-Hellman - like fast OT algorithm.

## Performance

| Algorithm    |      ns/op |   ops/s |
| :----------- | ---------: | ------: |
| RSA-512      |     252557 |    3960 |
| RSA-1024     |    1256961 |     796 |
| RSA-2048     |    7785958 |     128 |
| CO-batch-1   |     170791 |    5855 |
| CO-batch-2   |     269399 |    7424 |
| CO-batch-4   |     468161 |    8544 |
| CO-batch-8   |     877664 |    9115 |
| CO-batch-16  |    1706184 |    9378 |
| CO-batch-32  |    3273137 |    9777 |
| CO-batch-64  |    6480310 |    9876 |
| CO-batch-128 |   12845639 |    9964 |
