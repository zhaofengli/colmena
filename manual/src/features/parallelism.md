# Parallelism

Colmena is built from the ground up to support parallel deployments.
Evaluation, build, and deployment of node configurations can happen at the same time.
This parallelism can be controlled primarily through two flags:

**`--limit <number>`**

Number of hosts to deploy at once in the final step (pushing closures and activating new profiles). The default value is 10.

**`--eval-node-limit <number>`**

By default, Colmena will automatically determine the maximum number of nodes to evaluate at the same time according to available RAM.
This flag allows you to set the limit to a predetermined value.

