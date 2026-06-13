$ErrorActionPreference = "Stop"

$documentPath = "C:\PFE-security\docs\PFE_report_corrected_consistent.docx"
$word = New-Object -ComObject Word.Application
$word.Visible = $false
$word.DisplayAlerts = 0

try {
    $doc = $word.Documents.Open($documentPath)
    foreach ($table in $doc.Tables) {
        $text = $table.Range.Text
        if ($text -like "*Requirement area*" -and $text -like "*Pre-execution control*") {
            $table.Range.Style = "Normal"
            $table.Rows.Item(1).Range.Bold = 1
            break
        }
    }

    foreach ($toc in $doc.TablesOfContents) {
        $toc.Update()
    }
    $doc.Fields.Update() | Out-Null
    $doc.Save()
    $doc.Close()
}
finally {
    if ($null -ne $doc) {
        try { $doc.Close($false) } catch {}
    }
    $word.Quit()
    [System.Runtime.InteropServices.Marshal]::ReleaseComObject($word) | Out-Null
    [GC]::Collect()
    [GC]::WaitForPendingFinalizers()
}
