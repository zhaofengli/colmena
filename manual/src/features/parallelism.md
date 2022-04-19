# Parallelism

Colmena is built from the ground up to support parallel deployments.
Evaluation, build, and deployment of node configurations can happen at the same time.

## Configuration

The parallelism of Colmena can be controlled through two flags:

**`--limit <number>`**

Number of hosts to deploy at once in the final step (pushing closures and activating new profiles). The default value is 10.

**`--eval-node-limit <number>`**

By default, Colmena will automatically determine the maximum number of nodes to evaluate at the same time according to available RAM.
This flag allows you to set the limit to a predetermined value.

## Parallel Evaluation (Experimental)

By default, Colmena evaluates nodes in batches according to available RAM using Nix's built-in single-threaded evaluator.
Experimental support is available for using [nix-eval-jobs](https://github.com/nix-community/nix-eval-jobs) as the evaluator.

When nix-eval-jobs is enabled via `--evaluator streaming`, evaluation is parallelized with deployment processes kicked off as individual nodes finish evaluating.
