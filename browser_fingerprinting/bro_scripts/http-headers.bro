module HTTPHeaders;

export
{
    redef enum Log::ID += { LOG };

    type Info: record
    {
        ts:					    time &log;
        origin:				string &log;
        useragent:			    string &log;
        header_events_json:	string &log;
    };

    type header_info_record_type: record
    {
        ## Header name and value.
        name:         string;
        value:        string;
    };

    ## A type alias for a vector of header_info_records.
    type header_info_vector_type: vector of header_info_record_type;

}

redef record connection += {
    header_info_vector:        header_info_vector_type  &optional;
};

event bro_init()
{
    Log::create_stream(HTTPHeaders::LOG, [$columns=Info]);
}

# These events just init the vector, the whole http object gets wiped w/each request/reply
event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string)
        {
        c$http$header_info_vector = vector();
        }

event http_reply(c: connection, version: string, code: count, reason: string)
        {
        c$http$header_info_vector = vector();
        }

function vector_to_json_string(info_vector: header_info_vector_type): string
{
    local json_string: string;
    local escape_chars: string;
    local key: string;
    local value: string;
    local svalue: string;
    escape_chars = "\\\/\b\f\n\r\t\"";
    json_string = "[";
    for ( i in info_vector )
        {
            key = string_escape(info_vector[i]$name, escape_chars);
            value = info_vector[i]$value;
            value = to_string_literal(value);
            value = subst_string(value, "\\x", "\\u00"); # Replacing any hex escapes
            value = string_escape(value, escape_chars);

            # Stubbing out Cookie for now
            if (key == "COOKIE") { value = "-";}

            json_string += "{\"" + key + "\"" + ":" + "\"" + value + "\"},";
        }

    # Remove the last comma and add the closing bracket
    return cut_tail(json_string, 1) + "]";

}

event http_header(c: connection, is_orig: bool, name: string, value: string)
{
    local header_record: HTTP::header_info_record;
    local vector_size: int;

    if ( ! c?$http || ! c$http?$header_info_vector )
        return;

    # Add this http header info to the vector
    header_record$name = name;
    header_record$value = value;

    # Get current size of vector and add the record to the end
    c$http$header_info_vector[|c$http$header_info_vector|] = header_record;
}

event http_all_headers(c: connection, is_orig: bool, hlist: mime_header_list)
{
    local my_log: Info;
    local origin: string;
    local user_agent: string;
    local event_json_string: string;

    # Is the header from a client request or server response
    if ( is_orig )
        origin = "client";
    else
        origin = "server";

    # If we don't have a header_info_vector than punt
    if ( ! c?$http || ! c$http?$header_info_vector )
        return;

    print c$http$header_info_vector;

    # At this point our c$header_info_vector should contain all the
    # name/value pairs associated with the header, so will turn the
    # vector into a JSON string and add it to our log file.
    event_json_string = vector_to_json_string(c$http$header_info_vector);

    # Okay now set the user agent field
    user_agent = "nouseragentpresent-clicksecurity-lulz";
    for ( i in hlist )
    {
        if ( origin == "client" )
            if ( hlist[i]$name == "USER-AGENT" ){user_agent = hlist[i]$value;}
        if ( origin == "server" )
            if ( hlist[i]$name == "SERVER" ){user_agent = hlist[i]$value;}
    }

    # Now add all the info and the event list to the log
    my_log = [$ts=c$start_time,
        $useragent=fmt("%s", user_agent),
        $origin=fmt("%s", origin),
        $header_events_json=fmt("%s", event_json_string)];
    Log::write(HTTPHeaders::LOG, my_log);
}
