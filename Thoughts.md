## Thoughts

Extracting some data points from each VirusTotal, IPInfo, and AbuseIPDB each presented unique challenges. 

1. VirusTotal was the most difficult, as at first I assumed they utilized an elegant anti-bot solution, but then realized the architecture was a SPA built with Polymer which renders content in a shadow DOM. I needed to wait for thr SPA to render, using a delay and polling with the aim of returning a character count of over 100 chars. Then to traverse the shadow DOM I used a recursive function that checks if node has shadowRoot and descends into it, then collects all TEXT_NODE content, and traverses all childNodes. After collecting all of the text utilised regex pattern matching and a bit of parsing to retreive the data. 

2. IPInfo utilised a JSON-LD structure with non-standard field names. This took some trial and error, a bit of parsing and some fallback parsing to match the required fields. 

3. AbuseIPDB was much more straightforward, with table row parsing I was able to detect the key value pairs needed to extract the correct data.

