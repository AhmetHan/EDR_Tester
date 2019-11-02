$option = [System.StringSplitOptions]::RemoveEmptyEntries
$urlCollection = "slvoody.top,zwpajbp.com,moijbvx.top,yxxatfi.info,sbyzqpo.xyz,polmhgd.space,aqfarux.space,zxfkbzr.net,bbctlvx.net,fwzklyf.biz,gwtysmm.com,hnrqmuy.biz,glaxjlc.net,pwdbdgb.biz,kutvpxo.top"
$separator = ","
$urlList = $urlCollection.Split($separator, $option)

foreach ($url in $urlList) {

    Invoke-WebRequest $url

    # Give feedback on how far we are
    Write-Host ("Initiated request for {0}" -f $url)
}