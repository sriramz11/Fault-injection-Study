# Fault-injection-Study
syscall fault-injection framework using kretprobes. The framework injects controlled errno failures into selected filesystem syscalls, executes workloads inside a sandbox, and analyzes failure propagation, cascades, and error realism. Extensive way to study syscalls and error codes generated. Sometimes makes you think kernel code is not perfect.
