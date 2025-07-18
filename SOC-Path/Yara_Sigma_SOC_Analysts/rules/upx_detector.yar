rule UPX_packed_executable
{

    meta:
    description = "Detects UPX-packed executables"

    strings:
    $string_1 = "UPX0"
    $string_2 = "UPX1"
    $string_3 = "UPX2"

    condition:
    all of them

}
