# idshwk4

## Sumstats for Summary Statistics 
- Detection Requirement
  - Detect http scan based on 404 response 
  - The attacker scan the website to look for vulnerabilities 
  - In the scanning process, a lot of 404 response will be generated because the attacker has no knowledge of the target site before scanning 
  - So we can detect the attacker through the 404 response 
  - But there are other scenarios will generate the 404 responses, too
    - site configuration error, user mistype
    - the spiders repeat crawling the pages not existed
    - downloading tools repeat download the failing url

- The Algorithm Requirement 
  - make 404 statistics on orig_h 
  - In every 10 minutes
    - if the count of 404 response > 2 
    - and if the 404 ratio > 20% (404 ratio = 404 response/all response) 
    - and if (the unique count of url response 404 / if the count of 404 response ) > 0.5 
    - then output “x.x.x.x is a scanner with y scan attempts on z urls” where
      - x.x.x.x is the orig_h, y is the count of 404 response , z is the unique count of url response 404 

- You Need 
  - Sumstats is option but not a requirement
  - you may use set, table and record to do the calculating
  - you may measure the time interval every time http_reply is triggered 
