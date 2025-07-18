rule dharma_ransomware
{

      meta:
          author = "Madhukar Raina"
          description = "Simple rule to detect strings from Dharma ransomware"
          reference = "https://www.virustotal.com/gui/file/bff6a1000a86f8edf3673d576786ec75b80bed0c458a8ca0bd52d12b74099071/behavior"

      strings:
          $string_pdb = {  433A5C6372797369735C52656C656173655C5044425C7061796C6F61642E706462 }
          $string_ssss = { 73 73 73 73 73 62 73 73 73 }

      condition:
          all of them

}
