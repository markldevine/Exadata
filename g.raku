#!/usr/bin/env raku

use Data::Dump::Tree;
use Grammar::Debugger;

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
    token log-record            { <log-record-herald> \s+ <message>                                         }
    token log-record-herald     { ^ \s+ <name-field> \s+ <datetime-field> \s+ <status-field>                }
    token name-field            { \d+ '_' \d+                                                               }
    token datetime-field        { \d\d\d\d '-' \d\d '-' \d\d 'T' \d\d ':' \d\d ':' \d\d '-' \d\d ':' \d\d   }
    token status-field          { \w+                                                                       }
    token not-log-record-herald { <!log-record-herald>                                                      }
    token message               { <not-log-record-herald>+                                                  }
}

ddt EXADATALOG-grammar.parse($data);

=finish

EXADATALOG-grammar.parse($data, :actions(EXADATALOG-actions.new));

class EXADATALOG-actions {
    has $.hmc is required;

    method dlpar-record ($/) {
        my Int $partition-number    = +$/<partition-field><partition-number>;
        %HMC{$!hmc}<LSPPARTITIONDLPAR>{$partition-number} = LSPPARTITIONDLPAR.new:
            :$partition-number,
            :model(~$/<partition-field><model-type><model>),
            :type(~$/<partition-field><model-type><type>),
            :serial-number(~$/<partition-field><serial-number>),
            :ip-address(~$/<partition-field><ip-address>),
            :active(?$/<active-field><active>),
            :os-name(~$/<os-field><os-name>),
            :os-vr(~$/<os-field><os-vr>),
            :os-level(~$/<os-field><os-level>),
        ;

    }
}
