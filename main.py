import asyncio
from pyppeteer import launch
import json
import time
import os
from collector import collect_headers, collect_cookies, collect_meta, collect_css_href, collect_script_src, collect_script_content
from detector import detect_headers, detect_cookies, detect_meta, detect_css, detect_scriptsrc, detect_scripts


async def main():
    start_time = time.time()
    browser = await launch(headless=True)
    page = await browser.newPage()

    with open('technolyzer.json', 'r') as f:
        tech_data = json.load(f)

    folder_path = './technologies/'
    for filename in os.listdir(folder_path):
        if filename.endswith('.json'):
            file_path = os.path.join(folder_path, filename)
            with open(file_path, 'r') as f:
                additional_tech_data = json.load(f)

                for tech_name, tech_attributes in additional_tech_data.items():
                    if tech_name not in tech_data:
                        tech_data[tech_name] = tech_attributes

    # collecting on response
    all_headers = await collect_headers(page)

    await page.goto('https://www.vuuniversitypress.com', { 'waitUntil': 'networkidle0'})

    # collecting on page networkidle0
    all_meta = await collect_meta(page)
    all_cookies = await collect_cookies(page)
    all_css = await collect_css_href(page)
    all_scriptsrc = await collect_script_src(page)
    # all_scripts = await collect_script_content(page)

    detected_techs = await detect_headers(all_headers, tech_data)
    if detected_techs:
        print(f"Detected Technologies in Headers: {', '.join(detected_techs)}")

    detected_from_cookies = await detect_cookies(all_cookies, tech_data)
    if detected_from_cookies:
        print(f"Detected Technologies in Cookies: {', '.join(detected_from_cookies)}")

    detected_from_meta = await detect_meta(all_meta, tech_data)
    if detected_from_meta:
        print(f"Detected Technologies in Meta tags: {', '.join(detected_from_meta)}")

    detected_from_css = await detect_css(all_css, tech_data)
    if detected_from_css:
        print(f"Detected Technologies in CSS sources: {', '.join(detected_from_css)}")

    detected_from_scriptsrc = await detect_scriptsrc(all_scriptsrc, tech_data)
    if detected_from_scriptsrc:
        print(f"Detected Technologies in JS sources: {', '.join(detected_from_scriptsrc)}")

    # detected_from_scripts = await detect_scripts(all_scripts, tech_data)
    # if detected_from_scripts:
    #     print(f"Detected Technologies in Scripts: {', '.join(detected_from_scripts)}")

    await browser.close()

    end_time = time.time()
    total_time = end_time - start_time

    print(f"Total time taken: {total_time:.3f} seconds")


asyncio.get_event_loop().run_until_complete(main())
