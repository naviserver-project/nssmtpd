# Author: Vlad Seryakov vlad@crystalballinc.com 
# March 2006

namespace eval smtpd {

   variable version "Smtpd version 2.6"
}

proc smtpd::init {} {

    set path "ns/server/[ns_info server]/module/nssmtpd"
    ns_smtpd relay set {*}[ns_config $path relaydomains]
    ns_log notice "smtpd::init: Relay Domains: [ns_smtpd relay get]"
    ns_smtpd local set {*}[ns_config $path localdomains]
    ns_log notice "smtpd::init: Local Domains: [ns_smtpd local get]"
}

# Decode message header
proc smtpd::decodeHdr { str } {

    set b [string first "=?" $str]
    if { $b >= 0 } {
      set b [string first "?" $str [expr $b+2]]
      if { $b > 0 } {
        set e [string first "?=" $str $b]
        if { $e == -1 } { set e end } else { incr e -1 }
        switch [string index $str [expr $b+1]] {
         Q {
           set str [ns_smtpd decode qprint [string range $str [expr $b+3] $e]]
         }
         B {
           set str [ns_smtpd decode base64 [string range $str [expr $b+3] $e]]
         }
        }
      }
    }
    return $str
}

# Parses bounces
proc smtpd::decodeBounce { id body } {

    set sender_email ""
    set filters { 
        {The following addresses had permanent fatal errors -----[\r\n]+<?([^>\r\n]+)} {}
        {The following addresses had permanent delivery errors -----[\r\n]+<?([^>\r\n]+)} {}
        {The following addresses had delivery errors---[\r\n]+<?([^> \r\n]+)} {}
        {<([^>]+)>:[\r\n]+Sorry, no mailbox here by that name.} {}
        {Your message.+To:[ \t]+([^ \r\n]+)[\r\n]+.+did not reach the following recipient} {}
        {Your message cannot be delivered to the following recipients:.+Recipient address: ([^ \r\n]+)} {}
        {Failed addresses follow:.+<([^>]+)>} {}
        {[\r\n]+([^ \t]+) - no such user here.} {}
        {qmail-send.+permanent error.+<([^>]+)>:} {}
        {Receiver not found: ([^ \r\n\t]+)} {%s@compuserve.com}
        {Failed to deliver to '<([^>]+)>'} {}
        {The following address\(es\) failed:[\r\n\t ]+([^ \t\r\n]+)} {}
        {User<([^>]+)>.+550 Invalid recipient} {}
        {Delivery to the following recipients failed.[\r\n\t ]+([^ \t\r\n]+)} {}
        {<([^>]+)>:[\r\n]+Sorry.+control/locals file, so I don't treat it as local} {}
        {RCPT To:<([^>]+)>.+550} {}
        {550.*<([^>]+)>... User unknown} {}
        {550.*unknown user <([^<]+)>} {}
        {could not be delivered.+The .+ program[^<]+<([^<]+)>} {}
        {The following text was generated during the delivery attempt:------ ([^ ]+) ------} {}
        {The following addresses were not valid[\r\n\t ]+<([^>]+)>} {}
        {These addresses were rejected:[\r\n\t ]+([^ \t\r\n]+)} {}
        {Unexpected recipient failure - 553 5.3.0 <([^>]+)>} {}
        {not able to deliver to the following addresses.[\r\n\t ]+<([^>]+)>} {}
        {cannot be sent to the following addresses.[\r\n\t ]+<([^>]+)>} {}
        {was not delivered to:[\r\n\t ]+([^ \r\n]+)} {}
        {<([^>]+)>  delivery failed; will not continue trying} {}
        {User mailbox exceeds allowed[^:]+: ([^ \n\r\t]+)} {}
        {could not be delivered[^<]+<([^>]+)>:} {}
        {undeliverable[^<]+<([^@]+@[^>]+)>} {}
        {could not be delivered.+Bad name:[ \t]+([^ \r\n\t]+)} {%s@oracle.com}
    }

    foreach { filter data } $filters {
      if { [regexp -nocase $filter $body d sender_email] } { 
        if { $data ne "" } { set sender_email [format $data $sender_email] }
        break
      }
    }
    if { $sender_email ne "" } {
      foreach rcpt [ns_smtpd getrcpt $id] {
        foreach { user_email user_flags spam_score } $rcpt {}
        ns_log Error smtpd::decodeBounce: $id: $user_email: $sender_email
      }
    }
    return $sender_email
}

# Mailing list/Sender detection
proc smtpd::decodeSender { id } {

    set From [ns_smtpd getfrom $id]
    if { [set Sender [ns_smtpd checkemail [ns_smtpd gethdr $id Sender]]] ne "" } {
      return $Sender
    }
    if { [set ReplyTo [ns_smtpd checkemail [ns_smtpd gethdr $id Reply-To]]] ne "" && $ReplyTo ne $From } {
      return $ReplyTo
    }
    if { [set XSender [ns_smtpd checkemail [ns_smtpd gethdr $id X-Sender]]] ne "" } {
      return $XSender
    }
    # Try for old/obsolete mailing lists
    if { [ns_smtpd gethdr $id Mailing-List] ne "" ||
         [ns_smtpd gethdr $id List-Help] ne "" ||
         [ns_smtpd gethdr $id List-Unsubscribe] ne "" ||
         [ns_smtpd gethdr $id Precedence] in {"bulk" "list"}
     } {
	if { $ReplyTo ne "" } {
	    return $ReplyTo
	} else {
	    return $From
	}
    }
    return $From
}

proc smtpd::helo { id } {
    ns_log Debug(smtpd) "### smtpd::helo $id"
}

proc smtpd::mail { id } {
    ns_log Debug(smtpd) "### smtpd::mail $id"
}

proc smtpd::rcpt { id } {
   
    # Current recipient
    lassign [ns_smtpd getrcpt $id 0] user_email user_flags spam_score

    ns_log Debug(smtpd) "### smtpd::rcpt $id $user_email ($user_flags & [ns_smtpd flag RELAY])"
    
    # Non-relayable user, just pass it through
    if { !($user_flags & [ns_smtpd flag RELAY]) } {
	ns_smtpd setflag $id 0 VERIFIED
	ns_log Debug(smtpd) "### smtpd::rcpt $id $user_email .... pass through"
	return
    }
    # Example of checking by recipient
    switch -regexp -- $user_email {
     "joe@domain.com" -
     "joe@localhost" {
        # User is not allowed to receive any mail
        ns_smtpd setreply $id "550 ${user_email}... User unknown\r\n"
        ns_smtpd delrcpt $id 0
	ns_log Debug(smtpd) "### smtpd::rcpt $id $user_email .... not allowed"
        return
     }
     
     default {
	 # Check everything for this domain
	 ns_smtpd setflag $id 0 VIRUSCHECK
	 ns_smtpd setflag $id 0 SPAMCHECK
	 #return
     }
    }
    ns_log Debug(smtpd) "### smtpd::rcpt $id $user_email VERIFIED"

    # All other emails are allowed
    ns_smtpd setflag $id 0 VERIFIED
}

proc smtpd::data { id } {
    ns_log Debug(smtpd) "### smtpd::data $id"

    # Global connection flags
    set conn_flags [ns_smtpd getflag $id -1]
    # Sender email
    set sender_email [smtpd::decodeSender $id]
    # Subject from the headers
    set subject [ns_smtpd gethdr $id Subject]
    # Special headers
    set signature [ns_smtpd gethdr $id X-Smtpd-Signature]
    set virus_status [ns_smtpd gethdr $id X-Smtpd-Virus-Status]
    # Message data
    lassign [ns_smtpd getbody $id] body body_offset body_size
    
    # Find users who needs verification
    foreach rcpt [ns_smtpd getrcpt $id] {
	lassign $rcpt deliver_email user_flags spam_score
	# Non-relayable user
	if { !($user_flags & [ns_smtpd flag RELAY]) } {
	    ns_log Debug(smtpd) "### smtpd::data $id $ $rcpt .... Non-relayable"
	    continue
	}
	# SPAM detected
	if { $user_flags & [ns_smtpd flag GOTSPAM] } {
	    ns_log Debug(smtpd) "### smtpd::data $id $ $rcpt .... GOTSPAM"
	    continue
	}
	# Already delivered user
	if { $user_flags & [ns_smtpd flag DELIVERED] } {
	    ns_log Debug(smtpd) "### smtpd::data $id $ $rcpt .... DELIVERED"
	    continue
	}
	# Virus detected
	if { $conn_flags & [ns_smtpd flag GOTVIRUS] } {
	    ns_log Debug(smtpd) "### smtpd::data $id $ $rcpt .... GOTVIRUS"
	    continue
	}
	# Recipient is okay
	set users($deliver_email) $spam_score
    }
    if { [array size users] > 0 } {
      # Build attachments list
      foreach file [ns_smtpd gethdrs $id X-Smtpd-File] {
        append attachments $file " "
      }
      # Save the message in the database or do other things to the message,
      # i will save in the mailbox just as an example
      if { [catch {
        set fd [open /tmp/mailbox a]
        puts $fd "From $sender_email [ns_fmttime [ns_time]]\n$body"
        close $fd
      } errmsg] } {
        ns_smtpd setflag $id -1 ABORT
        ns_log Error smtpd:data: $errmsg
        ns_smtpd setreply $id "421 Transaction failed (Msg)\r\n"
      }
    }
}


proc smtpd::error { id } {
    ns_log Debug(smtpd) "### smtpd::error $id"

    set line [ns_smtpd getline $id]
    # sendmail 550 user unknown reply
    if { [regexp -nocase {RCPT TO: <([^@ ]+@[^ ]+)>: 550} $line d user_email] } {
      ns_log notice "smtpd::error: $id: Dropping $user_email"
    }
}

