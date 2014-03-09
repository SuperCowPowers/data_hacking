module HTTP;

export {
    type header_info_record: record
    {
        ## Header name and value.
        name:         string;
        value:        string;
    };

    redef record Info += { header_info_vector: vector of header_info_record &optional; };
}
