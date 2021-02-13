<#
.Synopsis
    Gets a list of discovered apps based on uploaded log files.
.DESCRIPTION
    This function retrives traffic and usage information about discovered apps.
.EXAMPLE
    PS C:\> Get-MCASDiscoveredApp -StreamId $streamid | select name -First 5

    name
    ----
    1ShoppingCart
    ABC News
    ACTIVE
    AIM
    AT&T

    Retrieves the first 5 app names sorted alphabetically.

.EXAMPLE
    PS C:\> Get-MCASDiscoveredApp -All -StreamId $streamid | select name

    name
    ----
    1ShoppingCart
    ABC News
    ACTIVE
    AIM
    AT&T
    ...

    Retrieves all app names

.EXAMPLE
    PS C:\> Get-MCASDiscoveredApp -StreamId $streamid -Category SECURITY | select name,@{N='Total (MB)';E={"{0:N2}" -f ($_.trafficTotalBytes/1MB)}}

    name                   Total (MB)
    ----                   ----------
    Blue Coat              19.12
    Globalscape            0.00
    McAfee Control Console 1.28
    Symantec               0.20
    Websense               0.06

    In this example we pull back only discovered apps in the security category and display a table of names and Total traffic which we format to 2 decimal places and divide the totalTrafficBytes property by 1MB to show the traffic in MB.

#>
function Get-MCASDiscoveredApp {
    [CmdletBinding()]
    param
    (
        # Specifies the credential object containing tenant as username (e.g. 'contoso.us.portal.cloudappsecurity.com') and the 64-character hexadecimal Oauth token as the password.
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSCredential]$Credential = $CASCredential,

        <#
        # Specifies the property by which to sort the results. Set to 'Name' by default. Possible Values: 'UserName','LastSeen'.
        [Parameter(ParameterSetName='List', Mandatory=$false)]
        [ValidateSet('IpCount','LastUsed','Name','Transactions','Upload','UserCount')]
        [ValidateNotNullOrEmpty()]
        [string]$SortBy='Name',

        # Specifies the direction in which to sort the results. Set to 'Ascending' by default. Possible Values: 'Ascending','Descending'.
        [Parameter(ParameterSetName='List', Mandatory=$false)]
        [ValidateSet('Ascending','Descending')]
        [ValidateNotNullOrEmpty()]
        [string]$SortDirection='Ascending',
        #>

        # Specifies the maximum number of results to retrieve when listing items matching the specified filter criteria. Set to 100 by default.
        [Parameter(ParameterSetName='List', Mandatory=$false)]
        [ValidateRange(1,100)]
        [ValidateNotNullOrEmpty()]
        [int]$ResultSetSize = 100,

        # Specifies to retrieve all apps that match filters
        [Parameter(ParameterSetName='List', Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [Switch]$All,

        # Specifies the number of records, from the beginning of the result set, to skip. Set to 0 by default.
        [Parameter(ParameterSetName='List', Mandatory=$false)]
        [ValidateScript({$_ -gt -1})]
        [int]$Skip = 0,

        ##### FILTER PARAMS #####

        <#
        # Limits results by category type. A preset list of categories are included.
        [Parameter(ParameterSetName='List', Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [app_category]$Category,
        #>

        <#
        # Limits the results by risk score range, for example '3-9'. Set to '1-10' by default.
        [Parameter(ParameterSetName='List', Mandatory=$false)]
        [ValidatePattern('^([1-9]|10)-([1-9]|10)$')]
        [ValidateNotNullOrEmpty()]
        [string]$ScoreRangeMin='1-10',
        #>

        <#
        [Parameter(ParameterSetName='List', Mandatory=$false)]
        [ValidateRange(1,10)]
        [ValidateNotNullOrEmpty()]
        [string]$ScoreRangeMin='1',

        [Parameter(ParameterSetName='List', Mandatory=$false)]
        [ValidateRange(1,10)]
        [ValidateNotNullOrEmpty()]
        [string]$ScoreRangeMax='10',
        #>

        # Limits the results by stream ID, for example '577d49d72b1c51a0762c61b0'. The stream ID can be found in the URL bar of the console when looking at the Discovery dashboard.
        [Parameter(ParameterSetName='List', Mandatory=$false, Position=0)]
        [ValidatePattern('^[A-Fa-f0-9]{24}$')]
        [ValidateNotNullOrEmpty()]
        [string]$StreamId,

        # Limits the results by time frame in days. Set to 90 days by default. (Options: 7, 30, or 90)
        [Parameter(ParameterSetName='List', Mandatory=$false)]
        [ValidateSet('7','30','90')]
        [ValidateNotNullOrEmpty()]
        [int]$TimeFrame=90,

        # Limits the results based on user count.
        [Parameter(ParameterSetName='List', Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [int]$UsersLessThan,

        # Limits the results based on user count.
        [Parameter(ParameterSetName='List', Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [int]$UsersGreaterThan,

        # Limits the results based on user count.
        [Parameter(ParameterSetName='List', Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [int]$RiskScoreMin = 0,

        # Limits the results based on user count.
        [Parameter(ParameterSetName='List', Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [int]$RiskScoreMax = 10,
       
        # Limits the results to apps with the specified tag(s).
        [Parameter(ParameterSetName='List', Mandatory=$false)]
        [ValidateSet('Sanctioned','Unsanctioned','None')]
        [ValidateNotNullOrEmpty()]
        [string[]]$Tag
    )

    if ($StreamId) {
        $stream = $StreamId
    }
    else {
        $stream = (Get-MCASStream | Where-Object {$_.displayName -eq 'Global View'}).Identity
    }

    #$body = @{'skip'=$Skip;'limit'=$ResultSetSize;'streamId'=$stream;'timeframe'=$TimeFrame} # Base request body


    $body = @{
        'skip'=$Skip;
        'limit'=$ResultSetSize;
        #'score'=$ScoreRange;
        'timeframe'=$TimeFrame;
        'streamId'=$stream
    } # Base request body


    <#
    if ($Category) {
        $body += @{'category'="SAASDB_CATEGORY_$Category"}
    }
    #>



    #region ----------------------------SORTING----------------------------
<#
    if ($SortBy -xor $SortDirection) {throw 'Error: When specifying either the -SortBy or the -SortDirection parameters, you must specify both parameters.'}

    # Add sort direction to request body, if specified
    if ($SortDirection) {$body.Add('sortDirection',$SortDirection.TrimEnd('ending').ToLower())}

    # Add sort field to request body, if specified
    switch ($SortBy) {
        'Name'         {$body.Add('sortField','name')}
        'UserCount'    {$body.Add('sortField','usersCount')}
        'IpCount'      {$body.Add('sortField','ipAddressesCount')}
        'LastUsed'     {$body.Add('sortField','lastUsed')}
        'Upload'       {$body.Add('sortField','trafficUploadedBytes')}
        'Transactions' {$body.Add('sortField','trafficTotalEvents')}
    }
    #if ($SortBy) {$body.Add('sortField',$SortBy)}
#>
    #endregion ----------------------------SORTING----------------------------


    #region ----------------------------FILTERING----------------------------

    $filterSet = @() # Filter set array

    #if ($Tag) {$filterSet += @{'tag'=    @{'eq'=$Tag}}} # Not working

    # UsersLessThan / UsersGreaterThan
        if ($UsersLessThan -or $UsersGreaterThan){ 
            $filterSet += @{'users' = @{} 
            }
            $FilterName = "users"
        }
        # UsersLessThan
        if ($UsersLessThan) { $filterSet.($FilterName).add('lt', $UsersLessThan ) }
        # UsersGreaterThan
        if ($UsersGreaterThan) { $filterSet.($FilterName).add('gt' , $UsersGreaterThan ) }

        
    # RiskScoreMin / RiskScoreMax
        if ($RiskScoreMin -or $RiskScoreMax){ 
            $filterSet += @{'score' = @{} 
            }
            $FilterName = "score"
        }
        # RiskScoreRange
        if ($RiskScoreMin -or $RiskScoreMax) { $filterSet.($FilterName).add('eq', @($RiskScoreMin, $RiskScoreMax) ) }     # UsersGreaterThan


    #endregion ----------------------------FILTERING----------------------------

    try {
        if ($All){
            $body.limit = 100
            do{
                $rawresponse = Invoke-MCASRestMethod -Credential $Credential -Path "/api/v1/discovery/discovered_apps/" -Method Post -Body $body -FilterSet $filterSet
                $response += $rawresponse.data
                $body.skip += 100
            } while ($response.count % 100 -eq 0)
        }
        else{
            $rawresponse = Invoke-MCASRestMethod -Credential $Credential -Path "/api/v1/discovery/discovered_apps/" -Method Post -Body $body -FilterSet $filterSet
            $response = $rawresponse.data
        }
    }
    catch {
        throw "Error calling MCAS API. The exception was: $_"
    }
    $response
}