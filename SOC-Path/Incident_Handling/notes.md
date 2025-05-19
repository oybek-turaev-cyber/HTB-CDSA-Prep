# Incident Handling
- two main activities >> `investigating` & `recovery`
- `jump bag` >> a bag with all necessary tools
- `DMARC` >> email protection to block the suspicious email requests which pretends coming from your
    organization or domain
    - built on top of the `SPF` / `DKIM`
    - Filtering can be applied with status `DMARC failed or passed` message on email headers
    - however, it may cause: *High false-positives* since some emails are sent on behalf of via some
        email sending service >> they will be highlighted as `DMARC failed` >> requires further
        testing

- `AMSI` >> Antimalware Scan Interface (AMSI) helps you defend against malware
- `LOLBin or LOLbas-project` >> application whitelisting bypasses

- `Indicator of Compromise` IOC >>  special languages such as `OpenIOC` or `YARA` to share IOCs in a
    - standard manner
    - During we need to ensure that only connection protocols and tools **that don't cache credentials upon a successful login**
    - are utilized (such as WinRM).
    - When `PsExec` is used with explicit credentials, those credentials are cached on the remote machine.
    - When `PsExec` is used without credentials, no cache on the remote server
    -
-
