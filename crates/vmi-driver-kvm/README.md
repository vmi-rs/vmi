<!-- readme start -->
VMI driver for KVM.

The driver introspects a running VM through the KVM VMI interface of the
host kernel. It takes the VM fd and the vCPU fds of the VM, which
`kvm::attach::from_pid` duplicates from a running VMM process.

Guest memory is mapped through the `vmi_fd` in host pages, and KVM keys
memory access permissions and view remaps by host page as well. A guest
page smaller than a host page is served as a window into the host page that
holds it. Protection and view changes then apply to the whole host page.
<!-- readme end -->
