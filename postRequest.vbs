' Please check your proxy event logs for detecting vbs type of rat family write correct siem rules
' user agent string field contains unique values and request url endswith .php or contains .php?
' what is the response your av or edr solution when this script run! 
' URL to open....
' Referance topic:https://www.computerhope.com/forum/index.php?topic=126519.0
sUrl = "http://www.testsite.com/page.php"
'POST Request to send.
sRequest = "varname=value&varname=value"

HTTPPost sUrl, sRequest

Function HTTPPost(sUrl, sRequest)
  set oHTTP = CreateObject("Microsoft.XMLHTTP")
  oHTTP.open "POST", sUrl,false
  oHTTP.setRequestHeader "Content-Type", "application/x-www-form-urlencoded"
  oHTTP.setRequestHeader "Content-Length", Len(sRequest)
  oHTTP.send sRequest
  HTTPPost = oHTTP.responseText
 End Function
