# Author : LTJAX, this code made for practicing on writing zeek sig code.

signature LFI {
    ip-proto == tcp
    dst-port == 80
    # Detect file://
    payload /.*file:\/\//.*
    #detect ../
    payload /.*\.\.\/\.\.\//.*
    #Detect php://
    payload /.*php:\/\//.*
    # Detect null byte injection
    payload /.*%00.*/
    # Detect directory traversal
    payload /.*\.\.[\/\\].*/
    event "LFI FOUND"
}

signature Command-execution {
    ip-proto == tcp
    dst-port == 80
    # Detect ;
    payload /.*;.*/
    # Detect |
    payload /.*|.*/
    # Detect &&
    payload /.*&&.*/
    # Detect backticks
    payload /.*`.*/
    # Detect process substitution
    payload /.*\$\(.*/
    event "Command injection Found!"
}

signature File-upload {
    ip-proto == tcp
    dst-port == 80
    # Detect file that have .php extnsion on it
    payload /.*Content-Disposition: form-data; name=".*"; filename=".*\.(php|phps|phtml)"/
    event "Unwanted file-type detected !"
}

signature Sql-Injection {
    ip-proto == tcp
    dst-port == 80
    # Detect the word Union
    payload /.*UNION.*/
    # Detect the word SELECT
    payload /.*SELECT.*/
    # Detect time-based attacks
    payload /.*SLEEP\(\d+\).*/
    # Detect boolean-based attacks
    payload /.*AND\s+(TRUE|FALSE)\s+--.*/
    event "SQL injection Found!"
}

signature XSS {
    ip-proto == tcp
    dst-port == 80
    # Detect the common document.cookie attack
    payload /.*document\.cookie.*/
    # Detect if there is any src payload in the requset
    payload /.*src=.*/
    # Detect reflected XSS
    payload /.*<script>.*<\/script>.*/
    # Detect stored XSS
    payload /.*<img\s+src=.*onerror=.*>/
    event "XSS Found!"
}

signature XXE-Injection {
    ip-proto == tcp
    dst-port == 80
    payload /<!ENTITY.*SYSTEM.*http:/.*
    event "XXE Injection Found"
}

signature SSRF {
    ip-proto == tcp
    dst-port == 80
    payload /GET\s+http:\/\//
    event "SSRF Found"
}

signature SSTI {
    ip-proto == tcp
    dst-port == 80
    payload /\{\{.*\}\}/
    event "SSTI Found"
}