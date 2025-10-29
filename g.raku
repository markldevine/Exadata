#!/usr/bin/env raku

my $data = q:to/END/;
    3_1    2025-08-30T03:06:44-04:00    info        Advanced Intrusion Detection Environment (AIDE) detected potential changes to software on this system. The changes are listed in /var/log/aide/aide.log and also at the end of this alert message.
                                                    Summary : :
                                                    Total number of entries : 54096
                                                    Added entries : 1
                                                    Removed entries : 0
                                                    Changed entries : 0
    1_1    2025-08-14T07:18:41-04:00    critical    After initial accelerated space reclamation, file system / is 80% full, which is equal to or above the 80% threshold. Accelerated space reclamation will continue.
                                                    This alert will be cleared when file system / becomes less than 75% full.
                                                    Top three directories ordered by total space usage are as follows:
                                                    /opt        : 2.69G
                                                    /root        : 2.15G
                                                    /usr        : 1.76G
    1_2    2025-08-14T17:36:40-04:00    clear       File system / is 58% full, which is below the 75% threshold. Normal space reclamation will resume.
END

my grammar EXADATALOG-grammar {
    token TOP                   { <log-record>+                                                             }
    token log-record            { <log-record-start> || <log-record-continue>                               }
    token log-record-start      { ^^ <log-record-herald> \s+ <log-text>                                     }
    token log-record-herald     { \s* <name> \s+ <datetime> \s+ <status>                                    }
    token log-record-continue   { ^^ <!before <log-record-herald>> <log-text>                               }
    token name                  { \d+ '_' \d+                                                               }
    token datetime              { \d\d\d\d '-' \d\d '-' \d\d 'T' \d\d ':' \d\d ':' \d\d '-' \d\d ':' \d\d   }
    token status                { \w+                                                                       }
    token log-text              { .+? \n                                                                    }
}

class EXADATALOG-record {
    has Str         $.name      is required;
    has DateTime    $.datetime  is required;
    has Str         $.status    is required;
    has Str         @.message;
}

my @EXADATALOG-records;

class EXADATALOG-actions {
    method log-record-herald ($/) {
        @EXADATALOG-records.push:   EXADATALOG-record.new(
            :name(~$/<name>),
            :datetime(DateTime.new(~$/<datetime>)),
            :status(~$/<status>),
        );
    }

    method log-text ($/) {
        @EXADATALOG-records[* - 1].message.push: ~$/.chomp;
    }
}

EXADATALOG-grammar.parse($data, :actions(EXADATALOG-actions));

for @EXADATALOG-records -> $record {
    printf "%-6s%-28s%-10s\n", $record.name, $record.datetime, $record.status;
    printf "\t%s\n", $record.message.join("\n");
}

=finish
