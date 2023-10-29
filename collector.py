import asyncio
import requests

async def collect_headers(page):
    all_headers = []

    async def on_response(response):
        all_headers.append(response.headers)

    page.on('response', lambda res: asyncio.ensure_future(on_response(res)))

    return all_headers


async def collect_cookies(page):
    all_cookies = []

    cookies = await page.cookies()
    all_cookies.extend(cookies)

    return all_cookies


async def collect_meta(page):
    all_meta = []

    meta_elements = await page.querySelectorAll('meta')

    for element in meta_elements:
        name_attribute = await page.evaluate('(element) => element.getAttribute("name")', element)
        content_attribute = await page.evaluate('(element) => element.getAttribute("content")', element)
        all_meta.append({'name': name_attribute, 'content': content_attribute})

    return all_meta


async def collect_css_href(page):
    all_css_href = []
    css_elements = await page.querySelectorAll('link[rel="stylesheet"]')
    for element in css_elements:
        href_property = await element.getProperty('href')
        href_value = await href_property.jsonValue()
        all_css_href.append(href_value)
    return all_css_href


async def collect_script_src(page):
    all_script_src = []
    script_elements = await page.querySelectorAll('script[src]')
    for element in script_elements:
        src_property = await element.getProperty('src')
        src_value = await src_property.jsonValue()
        all_script_src.append(src_value)
    return all_script_src


async def collect_script_content(page):
    all_script_content = []

    inline_scripts = await page.querySelectorAll('script:not([src])')
    for element in inline_scripts:
        content = await page.evaluate('(element) => element.textContent', element)
        first_100_lines = '\n'.join(content.split('\n')[:100])
        all_script_content.append({"type": "inline", "content": first_100_lines})

    external_scripts = await page.querySelectorAll('script[src]')
    for element in external_scripts:
        src_property = await element.getProperty('src')
        src_value = await src_property.jsonValue()
        try:
            with requests.get(src_value, stream=True) as response:
                if response.status_code == 200:
                    first_100_lines = ''
                    for i, line in enumerate(response.iter_lines()):
                        if i >= 100:
                            break
                        first_100_lines += line.decode() + '\n'
                    all_script_content.append({"type": "external", "content": first_100_lines})
        except:
            print(f"Failed to fetch content from {src_value}")

    return all_script_content
