#!/bin/perl
#
# Prettify and fix pod2html output
#
# $Id: fixhtml.pl,v 1.1.1.1 2001-04-12 18:06:54 ndwinton Exp $
#

while (<>)
{
    # Insert style

    if (/\<\/HEAD\>/)
    {
	print <<'EOF';
<style>
<!--
body, p, h1, h2, h3, h4, h5, td {
    font-family: Verdana, Arial, Helvetica, sans-serif; 
}
h1, h2, h3, h4, h5 {
    color: blue;
}
p, td {
    font-size: 12pt;
}
pre {
    font-family: Courier New, Courier, monospace;
    font-size: 11pt;
}
code {
    font-family: Courier New, Courier, monospace;
    font-size: 12pt;
}
-->
</style>
EOF
    }

    # Fix double quotes

    s/``/\&#147;/g;
    s/''/\&#148;/g;

    # Fix single quotes

    s/'/\&#146;/g;

    # Fix em-dashes

    s/---/\&#151;/g;

    # Add </P> to the end of paragraphs

    if (/^\<P\>/ .. /^$/)
    {
	print("</P>\n") if (/^$/);
    }

    print;
}

