rule ChineScan_Local_Benign_Marker
{
    strings:
        $marker = "CHINESCAN_BENIGN_YARA_MARKER_81F2"
    condition:
        $marker
}
