import re


async def detect_headers(all_headers, tech_data):
    detected_techs = []

    # Dictionary to store headers in the suggested format
    unique_headers = {}

    ignore_list = [
        "age",
        "cache-control",
        "expires",
        "pragma",
        "x-content-options",
        "x-frame-options",
        "x-content-type-options",
        "x-xss-protection",
        "content-encoding",
        "content-type",
        "content-security-policy",
        "content-security-policy-report-only",
        "cross-origin-opener-policy",
        "cross-origin-opener-policy-report-only",
        "cross-origin-resource-policy",
        "report-to",
        "permissions-policy",
        "referrer-policy",
        "date",
        "etag",
        "last-modified",
        "strict-transport-security",
        "transfer-encoding",
        "accept-ranges",
        "content-length",
        "cf-cache-status",
        "cf-ray",
        "nel",
        "p3p",
        "origin-trial",
        "vary",
        "status",
        "x-amz-request-id",
        "x-accel-expires",
        "x-accel-date",
        "x-amz-id-2",
        "x-cache-lb",
        "x-77-nzt-ray",
        "x-77-pop",
        "x-77-cache",
        "x-77-nzt",
        "x-77-age",
        "x-age-lb",
        "access-control-allow-origin",
        "access-control-allow-headers",
        "access-control-allow-methods",
        "alt-svc",
        "timing-allow-origin"
    ]

    # Populate the unique_headers dictionary without deduplication
    for headers in all_headers:
        for header_name, header_value in headers.items():
            header_name_lower = header_name.lower()

            if header_name_lower in ignore_list:
                continue  # Skip processing headers in the ignore list

            if header_name_lower not in unique_headers:
                unique_headers[header_name_lower] = []

            # Trim Set-Cookie values to everything before the '='
            if header_name_lower == "set-cookie":
                header_value = header_value.split('=', 1)[0]

            unique_headers[header_name_lower].append(header_value.strip())  # Remove leading/trailing whitespace

    # Remove duplicate values within each header_name
    for header_name, header_values in unique_headers.items():
        unique_headers[header_name] = list(set(header_values))

    for tech_name, attributes in tech_data.items():
        header_patterns = attributes.get('headers', {})

        for header_name, pattern in header_patterns.items():
            # Convert header_name to lowercase for case-insensitive comparison
            header_name = header_name.lower()

            if header_name in unique_headers:
                for unique_value in unique_headers[header_name]:
                    if not pattern:
                        detected_techs.append(tech_name)
                    else:
                        if re.search(pattern, unique_value, re.IGNORECASE):
                            detected_techs.append(tech_name)

    return list(set(detected_techs))  # return unique technologies only


async def detect_cookies(all_cookies, tech_data):
    detected_techs = []

    # Create a set to store unique cookie names
    unique_cookie_names = set()

    for cookie in all_cookies:
        # Get the name of the cookie and convert it to lowercase for case-insensitive comparison
        cookie_name = cookie['name'].lower()

        # Check if the cookie name is unique
        if cookie_name not in unique_cookie_names:
            unique_cookie_names.add(cookie_name)

            for tech_name, tech_info in tech_data.items():
                for cookie_name_pattern, _ in tech_info.get('cookies', {}).items():
                    if re.search(cookie_name_pattern, cookie_name, re.IGNORECASE):
                        detected_techs.append(tech_name)
    return detected_techs


async def detect_meta(all_meta, tech_data):
    detected_techs = []

    for tech_name, attributes in tech_data.items():
        meta_patterns = attributes.get('meta', {})
        for meta_name, pattern in meta_patterns.items():
            for meta in all_meta:
                if meta['name'] == meta_name:
                    if re.search(pattern, meta['content'], re.IGNORECASE):
                        detected_techs.append(tech_name)

    return detected_techs


async def detect_css(all_css, tech_data):
    detected_techs = []

    for tech_name, attributes in tech_data.items():
        css_pattern = attributes.get('css', None)

        if css_pattern:
            for css_href in all_css:
                if re.search(re.escape(css_pattern), css_href, re.IGNORECASE):
                    detected_techs.append(tech_name)
                    break

    return detected_techs


async def detect_scriptsrc(all_scriptsrc, tech_data):
    detected_techs = []

    for tech_name, attributes in tech_data.items():
        scriptsrc_patterns = attributes.get('scriptSrc', None)
        if scriptsrc_patterns:
            if not isinstance(scriptsrc_patterns, list):
                scriptsrc_patterns = [scriptsrc_patterns]
            for pattern in scriptsrc_patterns:

                for script_src in all_scriptsrc:
                    if re.search(pattern, script_src, re.IGNORECASE):
                        detected_techs.append(tech_name)
                        break  # Stop searching if one match is found for this technology

    return detected_techs
