# domain generation algorithm test with powershell
# https://twitter.com/DGAFeedAlerts/with_replies
# https://osint.bambenekconsulting.com/feeds/dga-feed.txt
# Please check your perimeter security device responses and analyze security events then write siem rules alert security analysts!
$option = [System.StringSplitOptions]::RemoveEmptyEntries
$urlCollection = "slvoody.top,zwpajbp.com,moijbvx.top,yxxatfi.info,sbyzqpo.xyz,polmhgd.space,aqfarux.space,zxfkbzr.net,bbctlvx.net,fwzklyf.biz,gwtysmm.com,hnrqmuy.biz,glaxjlc.net,pwdbdgb.biz,kutvpxo.top,jukqfxpgqqtppvk.info,bckwqtwxxaean.pro,byecoplnmsp.info,ttsglrljdmlvxcdgaugdssbs.com,uznnjdqeyif.com,1rw6av6hhzoxta8va5c5wf6y.com,hzpmqjppnvysezp.info,pztlbuwhufeylxyiduvsrcmb.com,w2zngc1neuepb1b6ablc3gwqh6.com"
$separator = ","
$urlList = $urlCollection.Split($separator, $option)

foreach ($url in $urlList) {

    Invoke-WebRequest $url

    # Give feedback on how far we are
    Write-Host ("Initiated request for {0}" -f $url)
}
