<!-- readme start -->
VMI driver for KVM. Implements the full driver trait family over the KVM VMI
uAPI (`vmi_fd`, per-vCPU event rings, fault-based guest-memory mmap). Construct
with `VmiKvmDriver::new(vm_fd, vcpu_fds)`; obtain the fds with
`kvm::attach::from_pid(pid)`.
<!-- readme end -->
