use std::net::IpAddr;

use vmi::{
    Va, VmiContext, VmiError, VmiEventResponse, VmiOs,
    driver::VmiRead,
    os::windows::{ArchAdapter, WindowsOs},
    utils::reactor::Action,
};
use zerocopy::{FromBytes, IntoBytes};

/// Corresponds to `enum FWPS_BUILTIN_LAYERS`.
#[derive(Copy, Clone, PartialEq, Eq)]
struct FwpsLayer(u16);

impl FwpsLayer {
    /// Corresponds to `FWPS_LAYER_INBOUND_TRANSPORT_V4`.
    const INBOUND_TRANSPORT_V4: Self = Self(12);

    /// Corresponds to `FWPS_LAYER_INBOUND_TRANSPORT_V6`.
    const INBOUND_TRANSPORT_V6: Self = Self(14);

    /// Corresponds to `FWPS_LAYER_OUTBOUND_TRANSPORT_V4`.
    const OUTBOUND_TRANSPORT_V4: Self = Self(16);

    /// Corresponds to `FWPS_LAYER_OUTBOUND_TRANSPORT_V6`.
    const OUTBOUND_TRANSPORT_V6: Self = Self(18);

    /// Corresponds to `FWPS_LAYER_ALE_AUTH_CONNECT_V4`.
    const ALE_AUTH_CONNECT_V4: Self = Self(48);

    /// Corresponds to `FWPS_LAYER_ALE_AUTH_CONNECT_V6`.
    const ALE_AUTH_CONNECT_V6: Self = Self(50);

    /// Corresponds to `FWPS_LAYER_ALE_FLOW_ESTABLISHED_V4`.
    const ALE_FLOW_ESTABLISHED_V4: Self = Self(52);

    /// Corresponds to `FWPS_LAYER_ALE_FLOW_ESTABLISHED_V6`.
    const ALE_FLOW_ESTABLISHED_V6: Self = Self(54);

    fn network_5tuple_indexes(self) -> Option<(u64, u64, u64, u64, u64)> {
        // enum FWPS_FIELDS_ALE_AUTH_CONNECT_V4 & _V6 (common fields) {
        const FWPS_FIELD_IP_LOCAL_ADDRESS: u64 = 2;
        const FWPS_FIELD_IP_LOCAL_PORT: u64 = 4;
        const FWPS_FIELD_IP_PROTOCOL: u64 = 5;
        const FWPS_FIELD_IP_REMOTE_ADDRESS: u64 = 6;
        const FWPS_FIELD_IP_REMOTE_PORT: u64 = 7;
        // }

        match self {
            FwpsLayer::ALE_AUTH_CONNECT_V4
            | FwpsLayer::ALE_AUTH_CONNECT_V6
            | FwpsLayer::ALE_FLOW_ESTABLISHED_V4
            | FwpsLayer::ALE_FLOW_ESTABLISHED_V6 => Some((
                FWPS_FIELD_IP_PROTOCOL,
                FWPS_FIELD_IP_LOCAL_ADDRESS,
                FWPS_FIELD_IP_LOCAL_PORT,
                FWPS_FIELD_IP_REMOTE_ADDRESS,
                FWPS_FIELD_IP_REMOTE_PORT,
            )),
            // Unknown layer.
            _ => None,
        }
    }
}

impl std::fmt::Debug for FwpsLayer {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let name = match *self {
            Self::INBOUND_TRANSPORT_V4 => "FWPS_LAYER_INBOUND_TRANSPORT_V4",
            Self::INBOUND_TRANSPORT_V6 => "FWPS_LAYER_INBOUND_TRANSPORT_V6",
            Self::OUTBOUND_TRANSPORT_V4 => "FWPS_LAYER_OUTBOUND_TRANSPORT_V4",
            Self::OUTBOUND_TRANSPORT_V6 => "FWPS_LAYER_OUTBOUND_TRANSPORT_V6",
            Self::ALE_AUTH_CONNECT_V4 => "FWPS_LAYER_ALE_AUTH_CONNECT_V4",
            Self::ALE_AUTH_CONNECT_V6 => "FWPS_LAYER_ALE_AUTH_CONNECT_V6",
            Self::ALE_FLOW_ESTABLISHED_V4 => "FWPS_LAYER_ALE_FLOW_ESTABLISHED_V4",
            Self::ALE_FLOW_ESTABLISHED_V6 => "FWPS_LAYER_ALE_FLOW_ESTABLISHED_V6",
            _ => return self.0.fmt(f),
        };
        f.write_str(name)
    }
}

bitflags::bitflags! {
    /// Flags that can specified which entries are present
    /// in the FWPS_INCOMING_METADATA_VALUES0 structure.
    ///
    /// Corresponds to the `FWPS_METADATA_FIELD_*` constants.
    #[derive(Debug, Copy, Clone, PartialEq, Eq)]
    struct FwpsMetadataFields: u32 {
        const DISCARD_REASON = 0x00000001;
        const FLOW_HANDLE = 0x00000002;
        const IP_HEADER_SIZE = 0x00000004;
        const PROCESS_PATH = 0x00000008;
        const TOKEN = 0x00000010;
        const PROCESS_ID = 0x00000020;
        const SYSTEM_FLAGS = 0x00000040;
    }
}

/// Corresponds to `enum FWP_DATA_TYPE`.
#[repr(C)]
#[derive(Copy, Clone, PartialEq, Eq, FromBytes, IntoBytes)]
struct FwpDataType(u32);

impl FwpDataType {
    /// Corresponds to `FWP_EMPTY`.
    const EMPTY: Self = Self(0);

    /// Corresponds to `FWP_UINT8`.
    const UINT8: Self = Self(1);

    /// Corresponds to `FWP_UINT16`.
    const UINT16: Self = Self(2);

    /// Corresponds to `FWP_UINT32`.
    const UINT32: Self = Self(3);

    /// Corresponds to `FWP_UINT64`.
    const UINT64: Self = Self(4);

    /// Corresponds to `FWP_INT8`.
    const INT8: Self = Self(5);

    /// Corresponds to `FWP_INT16`.
    const INT16: Self = Self(6);

    /// Corresponds to `FWP_INT32`.
    const INT32: Self = Self(7);

    /// Corresponds to `FWP_INT64`.
    const INT64: Self = Self(8);

    // const FWP_FLOAT: u32 = 9;
    // const FWP_DOUBLE: u32 = 10;
    // const FWP_BYTE_ARRAY16_TYPE: u32 = 11;
    // const FWP_BYTE_BLOB_TYPE: u32 = 12;
    // const FWP_SID: u32 = 13;
    // const FWP_SECURITY_DESCRIPTOR_TYPE: u32 = 14;
    // const FWP_TOKEN_INFORMATION_TYPE: u32 = 15;
    // const FWP_TOKEN_ACCESS_INFORMATION_TYPE: u32 = 16;
    // const FWP_UNICODE_STRING_TYPE: u32 = 17;
    // const FWP_BYTE_ARRAY6_TYPE: u32 = 18;
    // const FWP_SINGLE_DATA_TYPE_MAX: u32 = 0xff;
    // const FWP_V4_ADDR_MASK: u32 = 0x100;
    // const FWP_V6_ADDR_MASK: u32 = 0x101;
    // const FWP_RANGE_TYPE: u32 = 0x102;
    // const FWP_DATA_TYPE_MAX: u32 = 0x103;
}

impl std::fmt::Debug for FwpDataType {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let name = match *self {
            Self::EMPTY => "FWP_EMPTY",
            Self::UINT8 => "FWP_UINT8",
            Self::UINT16 => "FWP_UINT16",
            Self::UINT32 => "FWP_UINT32",
            Self::UINT64 => "FWP_UINT64",
            Self::INT8 => "FWP_INT8",
            Self::INT16 => "FWP_INT16",
            Self::INT32 => "FWP_INT32",
            Self::INT64 => "FWP_INT64",
            _ => return self.0.fmt(f),
        };
        f.write_str(name)
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone, FromBytes, IntoBytes)]
struct FWP_VALUE0 {
    ty: FwpDataType, // enum FWP_DATA_TYPE
    _pad: u32,
    data: u64,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, FromBytes, IntoBytes)]
struct FWPS_INCOMING_VALUE0 {
    value: FWP_VALUE0, // FWP_VALUE0
}

#[repr(C)]
#[derive(Debug, Copy, Clone, FromBytes, IntoBytes)]
struct FWPS_INCOMING_VALUES0 {
    layerId: u16, // UINT16
    _pad: u16,
    valueCount: u32,    // UINT32
    incomingValue: u64, // FWPS_INCOMING_VALUE0*
}

#[repr(C)]
#[derive(Debug, Copy, Clone, FromBytes, IntoBytes)]
struct FWPS_DISCARD_METADATA0 {
    discardModule: u32, // enum FWPS_DISCARD_MODULE0
    discardReason: u32, // UINT32
    filterId: u64,      // UINT64
}

#[repr(C)]
#[derive(Debug, Copy, Clone, FromBytes, IntoBytes)]
struct FWPS_INCOMING_METADATA_VALUES0 {
    currentMetadataValues: u32,              // UINT32
    flags: u32,                              // UINT32
    reserved: u64,                           // UINT64
    discardMetadata: FWPS_DISCARD_METADATA0, // FWPS_DISCARD_METADATA0
    flowHandle: u64,                         // UINT64
    ipHeaderSize: u32,                       // UINT32
    transportHeaderSize: u32,                // UINT32
    processPath: u64,                        // FWP_BYTE_BLOB*
    token: u64,                              // UINT64
    processId: u64,                          // UINT64

                                             // ... we don't need the rest of the fields
}

/// Corresponds to `enum IPPROTO`.
#[derive(Copy, Clone, PartialEq, Eq)]
struct IpProtocol(u8);

impl IpProtocol {
    /// Corresponds to `IPPROTO_HOPOPTS`.
    const HOPOPTS: Self = Self(0);

    /// Corresponds to `IPPROTO_ICMP`.
    const ICMP: Self = Self(1);

    /// Corresponds to `IPPROTO_IGMP`.
    const IGMP: Self = Self(2);

    /// Corresponds to `IPPROTO_GGP`.
    const GGP: Self = Self(3);

    /// Corresponds to `IPPROTO_IPV4`.
    const IPV4: Self = Self(4);

    /// Corresponds to `IPPROTO_ST`.
    const ST: Self = Self(5);

    /// Corresponds to `IPPROTO_TCP`.
    const TCP: Self = Self(6);

    /// Corresponds to `IPPROTO_CBT`.
    const CBT: Self = Self(7);

    /// Corresponds to `IPPROTO_EGP`.
    const EGP: Self = Self(8);

    /// Corresponds to `IPPROTO_IGP`.
    const IGP: Self = Self(9);

    /// Corresponds to `IPPROTO_PUP`.
    const PUP: Self = Self(12);

    /// Corresponds to `IPPROTO_UDP`.
    const UDP: Self = Self(17);

    /// Corresponds to `IPPROTO_IDP`.
    const IDP: Self = Self(22);

    /// Corresponds to `IPPROTO_RDP`.
    const RDP: Self = Self(27);

    /// Corresponds to `IPPROTO_IPV6`.
    const IPV6: Self = Self(41);

    /// Corresponds to `IPPROTO_ROUTING`.
    const ROUTING: Self = Self(43);

    /// Corresponds to `IPPROTO_FRAGMENT`.
    const FRAGMENT: Self = Self(44);

    /// Corresponds to `IPPROTO_ESP`.
    const ESP: Self = Self(50);

    /// Corresponds to `IPPROTO_AH`.
    const AH: Self = Self(51);

    /// Corresponds to `IPPROTO_ICMPV6`.
    const ICMPV6: Self = Self(58);

    /// Corresponds to `IPPROTO_NONE`.
    const NONE: Self = Self(59);

    /// Corresponds to `IPPROTO_DSTOPTS`.
    const DSTOPTS: Self = Self(60);

    /// Corresponds to `IPPROTO_ND`.
    const ND: Self = Self(77);

    /// Corresponds to `IPPROTO_ICLFXBM`.
    const ICLFXBM: Self = Self(78);

    /// Corresponds to `IPPROTO_PIM`.
    const PIM: Self = Self(103);

    /// Corresponds to `IPPROTO_PGM`.
    const PGM: Self = Self(113);

    /// Corresponds to `IPPROTO_L2TP`.
    const L2TP: Self = Self(115);

    /// Corresponds to `IPPROTO_SCTP`.
    const SCTP: Self = Self(132);

    /// Corresponds to `IPPROTO_RAW`.
    const RAW: Self = Self(255);
}

impl std::fmt::Debug for IpProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let name = match *self {
            Self::HOPOPTS => "IPPROTO_HOPOPTS",
            Self::ICMP => "IPPROTO_ICMP",
            Self::IGMP => "IPPROTO_IGMP",
            Self::GGP => "IPPROTO_GGP",
            Self::IPV4 => "IPPROTO_IPV4",
            Self::ST => "IPPROTO_ST",
            Self::TCP => "IPPROTO_TCP",
            Self::CBT => "IPPROTO_CBT",
            Self::EGP => "IPPROTO_EGP",
            Self::IGP => "IPPROTO_IGP",
            Self::PUP => "IPPROTO_PUP",
            Self::UDP => "IPPROTO_UDP",
            Self::IDP => "IPPROTO_IDP",
            Self::RDP => "IPPROTO_RDP",
            Self::IPV6 => "IPPROTO_IPV6",
            Self::ROUTING => "IPPROTO_ROUTING",
            Self::FRAGMENT => "IPPROTO_FRAGMENT",
            Self::ESP => "IPPROTO_ESP",
            Self::AH => "IPPROTO_AH",
            Self::ICMPV6 => "IPPROTO_ICMPV6",
            Self::NONE => "IPPROTO_NONE",
            Self::DSTOPTS => "IPPROTO_DSTOPTS",
            Self::ND => "IPPROTO_ND",
            Self::ICLFXBM => "IPPROTO_ICLFXBM",
            Self::PIM => "IPPROTO_PIM",
            Self::PGM => "IPPROTO_PGM",
            Self::L2TP => "IPPROTO_L2TP",
            Self::SCTP => "IPPROTO_SCTP",
            Self::RAW => "IPPROTO_RAW",
            _ => return self.0.fmt(f),
        };
        f.write_str(name)
    }
}

/// Demonstrates how to log network connection attempts and flows.
pub fn KfdClassify<Driver>(
    vmi: &VmiContext<WindowsOs<Driver>>,
) -> Result<Action<<WindowsOs<Driver> as VmiOs>::Architecture>, VmiError>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    //
    // PVOID
    // NTAPI
    // KfdClassify (
    //     _In_ UINT16 layerId,
    //     _In_ const FWPS_INCOMING_VALUES* inFixedValues,
    //     _In_ const FWPS_INCOMING_METADATA_VALUES* inContext,
    //     _In_ PVOID packet,
    //     _In_ const FWPP_SHIM_PROVIDER_CONTEXT* shimProvContext,
    //     _Inout_ FWPS_CLASSIFY_OUT* classifyOut
    //     );
    //

    let layerId = FwpsLayer(vmi.os().function_argument(0)? as u16);
    let inFixedValues = Va(vmi.os().function_argument(1)?);
    let inContext = Va(vmi.os().function_argument(2)?);

    let (
        protocol_index,
        local_address_index,
        local_port_index,
        remote_address_index,
        remote_port_index,
    ) = match layerId.network_5tuple_indexes() {
        Some(indexes) => indexes,
        None => return Ok(Action::default()),
    };

    let incoming_values = vmi.read_struct::<FWPS_INCOMING_VALUES0>(inFixedValues)?;
    let incoming = Va(incoming_values.incomingValue);

    const SIZEOF_VALUE: u64 = size_of::<FWPS_INCOMING_VALUE0>() as u64;

    //
    // Protocol.
    //

    let protocol =
        vmi.read_struct::<FWPS_INCOMING_VALUE0>(incoming + protocol_index * SIZEOF_VALUE)?;

    if protocol.value.ty != FwpDataType::UINT8 {
        tracing::debug!(
            protocol_type = ?protocol.value.ty,
            expected = ?FwpDataType::UINT8,
            "unexpected protocol type"
        );
        return Ok(Action::default());
    }

    //
    // Local Address.
    //

    let local_address =
        vmi.read_struct::<FWPS_INCOMING_VALUE0>(incoming + local_address_index * SIZEOF_VALUE)?;

    if local_address.value.ty != FwpDataType::UINT32 {
        tracing::debug!(
            local_address_type = ?local_address.value.ty,
            expected = ?FwpDataType::UINT32,
            "unexpected local address type"
        );
        return Ok(Action::default());
    }

    //
    // Local Port.
    //

    let local_port =
        vmi.read_struct::<FWPS_INCOMING_VALUE0>(incoming + local_port_index * SIZEOF_VALUE)?;

    if local_port.value.ty != FwpDataType::UINT16 {
        tracing::debug!(
            local_port_type = ?local_port.value.ty,
            expected = ?FwpDataType::UINT16,
            "unexpected local port type"
        );
        return Ok(Action::default());
    }

    //
    // Remote Address.
    //

    let remote_address =
        vmi.read_struct::<FWPS_INCOMING_VALUE0>(incoming + remote_address_index * SIZEOF_VALUE)?;

    if remote_address.value.ty != FwpDataType::UINT32 {
        tracing::debug!(
            remote_address_type = ?remote_address.value.ty,
            expected = ?FwpDataType::UINT32,
            "unexpected remote address type"
        );
        return Ok(Action::default());
    }

    //
    // Remote Port.
    //

    let remote_port =
        vmi.read_struct::<FWPS_INCOMING_VALUE0>(incoming + remote_port_index * SIZEOF_VALUE)?;

    if remote_port.value.ty != FwpDataType::UINT16 {
        tracing::debug!(
            remote_port_type = ?remote_port.value.ty,
            expected = ?FwpDataType::UINT16,
            "unexpected remote port type"
        );
        return Ok(Action::default());
    }

    let protocol = IpProtocol(protocol.value.data as u8);
    let local_address = local_address.value.data as u32;
    let local_port = local_port.value.data as u16;
    let remote_address = remote_address.value.data as u32;
    let remote_port = remote_port.value.data as u16;

    let local_ip = IpAddr::from(local_address.to_be_bytes());
    let remote_ip = IpAddr::from(remote_address.to_be_bytes());

    // Fetch the most valuable information that can't be obtained
    // from the pcap: the process ID that initiated the connection.
    let context = vmi.read_struct::<FWPS_INCOMING_METADATA_VALUES0>(inContext)?;
    let metadata_values = FwpsMetadataFields::from_bits_retain(context.currentMetadataValues);
    let pid = if metadata_values.contains(FwpsMetadataFields::PROCESS_ID) {
        Some(context.processId)
    }
    else {
        None
    };

    tracing::info!(
        ?protocol,
        %local_ip,
        local_port,
        %remote_ip,
        remote_port,
        pid,
    );

    Ok(Action::default())
}

/// Demonstrates changing the behavior of a function.
///
/// In many places, the `tcpip.sys` driver does roughly the following:
///
/// ```ignore
/// if (KfdIsLayerEmpty(layerId)) {
///     // Early exit - no active filter for this layer.
///     return STATUS_SUCCESS;
/// }
/// ...
/// KfdClassify(layerId, ...);
/// ```
///
/// Problem is, there's no guarantee that any filter will be active
/// for the layers we're interested in.
///
/// By hooking `KfdIsLayerEmpty` and returning `FALSE` for the layers
/// we're interested in, we can ensure that `KfdClassify` will get called.
///
/// Note that calling `KfdClassify` without an active filter is not a problem.
/// The function will simply realize that there's no filter and return without
/// doing anything. But most importantly, we intercept its execution with its
/// valuable arguments.
pub fn KfdIsLayerEmpty<Driver>(
    vmi: &VmiContext<WindowsOs<Driver>>,
) -> Result<Action<<WindowsOs<Driver> as VmiOs>::Architecture>, VmiError>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    //
    // BOOLEAN
    // NTAPI
    // KfdIsLayerEmpty (
    //     _In_ UINT16 layerId
    //     );
    //

    let layerId = FwpsLayer(vmi.os().function_argument(0)? as u16);

    if !matches!(
        layerId,
        FwpsLayer::ALE_AUTH_CONNECT_V4
            | FwpsLayer::ALE_AUTH_CONNECT_V6
            | FwpsLayer::ALE_FLOW_ESTABLISHED_V4
            | FwpsLayer::ALE_FLOW_ESTABLISHED_V6
    ) {
        tracing::trace!(?layerId, "passing through");
        return Ok(Action::default());
    }

    tracing::trace!(?layerId, "overriding");

    let registers = vmi.return_from_function(0)?; // Return FALSE

    Ok(Action::Response(
        VmiEventResponse::default().with_registers(registers),
    ))
}
