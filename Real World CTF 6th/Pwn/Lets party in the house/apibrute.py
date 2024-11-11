import requests

url_base = "http://0.0.0.0:8080"

endpoints = [
    "/syno-api/security/ip_filter/deny",
    "/syno-api/security",
    "/syno-api/security/encryption_key",
    "/syno-api/recording/sd_card/speed_test",
    "/syno-api/recording/sd_card/format",
    "/syno-api/recording/sd_card/mount",
    "/syno-api/recording/sd_card/unmount",
    "/syno-api/recording/retrieve",
    "/syno-api/recording/download",
    "/syno-api/snapshot",
    "/syno-api/maintenance/reboot",
    "/syno-api/maintenance/firmware/upgrade",
    "/syno-api/security/https/upload_cert",
    "/syno-api/security/https/upload_key",
    "/syno-api/maintenance/log/retrieve",
    "/syno-api/maintenance/system/report",
    "/syno-api/login",
    "/syno-api/logout",
    "/syno-api/session",
    "/syno-api/stream_num",
    "/syno-api/security/connection",
    "/syno-api/manual/trigger/md",
    "/syno-api/manual/trigger/td",
    "/syno-api/manual/trigger/ad",
    "/syno-api/manual/trigger/disconn",
    "/syno-api/manual/trigger/ai",
    "/syno-api/maintenance/reset",
    "/syno-api/security/ca/upload_cert",
    "/syno-api/security/ca/upload_key",
    "/syno-api/camera_cap",
    "/syno-api/security/info/language",
    "/syno-api/security/info/mac",
    "/syno-api/security/info/serial_number",
    "/syno-api/activate",
    "/syno-api/security/info",
    "/syno-api/security/info/name",
    "/syno-api/security/info/model",
    "/syno-api/maintenance/firmware/version",
    "/syno-api/security/network/dhcp",
    "/syno-api/security/user",
    "/syno-api/date_time"
]

# Function to make requests and print results
def make_request(method, endpoint):
    url = url_base + endpoint
    data = "{hey:hey}"
    headers = {'Content-Type': 'application/json'}
    response = getattr(requests, method.lower())(url, headers=headers, data=data)
    return response.status_code


authorized_endpoints = []
for endpoint in endpoints:
    status_code_put = make_request("PUT", endpoint)
    status_code_post = make_request("POST", endpoint)
    status_code_delete = make_request("DELETE", endpoint)

    if status_code_post != 403 and status_code_post != 404 and status_code_post != 401:
        print("POST : "  + endpoint + "  " + str(status_code_post))
    if status_code_put != 403 and status_code_put != 404 and status_code_put != 401:
        print("PUT : "  + endpoint + "  " + str(status_code_put))
    if status_code_delete != 403 and status_code_delete != 404 and status_code_delete != 401:
        print("DELETE : "  + endpoint + "  " + str(status_code_delete))
