## Blog Post Title From First Header

During Christmas holiday, I was reviewing my Github account and I found a funny web applications that I developed for an universitary course. It's Meme Generator, which obviosly allow user to see communicaty-created meme and, if registered, to create its own memes.
Being an introductory course on web application development, security was unfortunately out-of-scope. I start thinking what could happen if I would expose the app on Internet. Would hackers be interested on breaking it? Would they be able to do that? Would they be able to find it in the very first place?
Let's try it.
Beside the application, I needed:
- A way to understand if something strange is happening on my web server.
- I would like to know what kind of requests reach it.
- A software to centralize all these information.

I found out that Wazuh can satisfy both point 1. and 3. Wazuh is an open-source XDR and SIEM solutions: this means that the agent can monitor the endpoint where application is hosted and figure out if some malicious actions is taking place; moreover the SIEM can collect telemetry data for future analysis.
Regarding point 2. I decided to use Suricata which is a IDS/IPS solution, therefore can help me to understand if some strange requests is hitting the server. Finally, I forwarded Suricata alerts to Wazuh SIEM.

I didn't plan to use an SSH honeypot in the first place, but after some trials, I thought it may be a good idea to make the server more attractive for the bad guys. After trying a bunch of open-source projects, I went with Cowrie ()

---

### This is a header

#### Some T-SQL Code

```tsql
SELECT This, [Is], A, Code, Block -- Using SSMS style syntax highlighting
    , REVERSE('abc')
FROM dbo.SomeTable s
    CROSS JOIN dbo.OtherTable o;
```

#### Some PowerShell Code

```powershell
Write-Host "This is a powershell Code block";

# There are many other languages you can use, but the style has to be loaded first

ForEach ($thing in $things) {
    Write-Output "It highlights it using the GitHub style"
}
```
