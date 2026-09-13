import json
from client.tapo_client import TapoClient


class TapoWapClient(TapoClient):
    DEFAULT_BASE_URL = "https://eu-wap.tplinkcloud.com"

    def __init__(self, base_url = DEFAULT_BASE_URL):
        super().__init__(base_url)

    @staticmethod
    def clean_none(data: dict) -> dict:
        for key, value in list(data.items()):
            if value is None:
                del data[key]
            elif isinstance(value, dict):
                TapoWapClient.clean_none(value)

        return data

    def send_request(self, method: str, params: dict = None):
        content = {}

        content["method"] = method

        if params:
            content["params"] = TapoWapClient.clean_none(params)

        return self._post_json("/", content)

    def login(self, email, password):
        return self.send_request("login", {
            "appType": "Tapo_Android",
            "cloudUserName": email,
            "cloudPassword": password,
            "terminalUUID": "0A950402-7224-46EB-A450-7362CDB902A2"
        })

    def do_login(self, email, password):
        response = self.login(email, password)

        self.token = response["token"]

        return response

    def add_device_user(self, device_id: str, owner_email: str, user_email: str):
            return self.send_request("addDeviceUser", {
                "deviceId": device_id,
                "ownerEmail": owner_email,
                "userEmail": user_email
            })

    def change_email(self, cloud_password: str, cloud_username: str, new_email: str):
        return self.send_request("changeEmail", {
            "cloudPassword": cloud_password,
            "cloudUserName": cloud_username,
            "newEmail": new_email
        })

    def change_phone(self, cloud_password: str, cloud_username: str, country: str, country_code: str, phone: str, verify_code: str):
        return self.send_request("changePhone", {
            "cloudPassword": cloud_password,
            "cloudUserName": cloud_username,
            "country": country,
            "countryCode": country_code,
            "phone": phone,
            "verifyCode": verify_code,
        })

    def check_password(self, cloud_password: str, cloud_username: str):
        return self.send_request("checkPassword", {
            "cloudPassword": cloud_password,
            "cloudUserName": cloud_username
        })

    def check_verify_code(self, action: str, cloud_username: str, verify_code: str):
        return self.send_request("checkVerifyCode", {
            "action": action,
            "cloudUserName": cloud_username,
            "verifyCode": verify_code
        })

    def get_account_info(self, cloud_user_name: str):
        return self.send_request("getAccountInfo", {
            "cloudUserName": cloud_user_name
        })

    def get_app_versions(self, app_package_name: str, locale: str, platform: str, version_code: int):
        return self.send_request("getAppVersions", {
            "appPackageName": app_package_name,
            "locale": locale,
            "platform": platform,
            "versionCode": version_code
        })

    def get_cloud_account_status(self, cloud_user_name: str):
        return self.send_request("getCloudAccountStatus", {
            "cloudUserName": cloud_user_name
        })

    def get_device_info(self, device_id: str):
        return self.send_request("getDeviceInfo", {
            "deviceId": device_id
        })

    def get_device_list(self, device_type: str = None, protocol: str = None):
        return self.send_request("getDeviceList", {
            "deviceType": device_type,
            "protocol": protocol
        })

    def get_device_user_info(self, device_id: str):
        return self.send_request("getDeviceUserInfo", {
            "deviceId": device_id
        })

    def get_fw_download_progress(self, device_id: str):
        return self.send_request("getFwDownloadProgress", {
            "deviceId": device_id
        })

    def get_intl_fw_list(self, device_id: str, fw_id: str, hw_id: str, oem_id: str, dev_fw_current_ver: str, locale: str = None):
        return self.send_request("getIntlFwList", {
            "deviceId": device_id,
            "fwId": fw_id,
            "hwId": hw_id,
            "oemId": oem_id,
            "devFwCurrentVer": dev_fw_current_ver,
            "locale": locale
        })

    def get_int_fw_versions(self, device_id: str, fw_id: str, hw_id: str, oem_id: str, dev_fw_current_ver: str, locale: str):
        return self.send_request("getIntlFwVersions", {
            "deviceId": device_id,
            "fwId": fw_id,
            "hwId": hw_id,
            "oemId": oem_id,
            "devFwCurrentVer": dev_fw_current_ver,
            "locale": locale
        })

    def get_legal_info(self):
        return self.send_request("getLegalInfo")

    def get_newest_app_version(self, app_package_name: str, locale: str, platform: str):
        return self.send_request("getNewestAppVersion", {
            "appPackageName": app_package_name,
            "locale": locale,
            "platform": platform
        })

    def get_notice(self):
        return self.send_request("getNotice")

    def get_reset_password_email(self, email: str, locale: str):
        return self.send_request("getResetPasswordEmail", {
            "email": email,
            "locale": locale
        })

    def get_subscribe_msg_type(self, app_type: str, device_token: str):
        return self.send_request("getSubscribeMsgType", {
            "appType": app_type,
            "device_token": device_token
        })

    def get_verify_code(self, cloud_username: str, action: str):
        return self.send_request("getVerifyCode", {
            "cloudUserName": cloud_username,
            "action": action
        })

    def hello_could(self, app_package_name: str, app_type: str, tcsp_ver: str, terminal_uuid: str):
        return self.send_request("helloCloud", {
            "appPackageName": app_package_name,
            "appType": app_type,
            "tcsp": tcsp_ver,
            "terminalUUID": terminal_uuid
        })

    def logout(self, cloud_username: str):
        return self.send_request("logout", {
            "cloudUserName": cloud_username
        })

    def modify_cloud_password(self):
        return self.send_request("modifyCloudPassword")

    def passtrough(self, device_id: str, request_data: dict = None):
        return self.send_request("passthrough", {
            "deviceId": device_id,
            "requestData": json.dumps(request_data)
        })

    def post_push_info(self, app_package_name: str, app_type: str, device_token: str, locale: str, mobile_type: str, terminal_uuid: str, version_code: int):
        return self.send_request("postPushInfo", {
            "appPackageName": app_package_name,
            "appType": app_type,
            "deviceToken": device_token,
            "locale": locale,
            "mobileType": mobile_type,
            "terminalUUID": terminal_uuid,
            "versionCode": version_code,
        })

    def refresh_token(self, app_type: str, refresh_token: str, terminal_uuid: str):
        return self.send_request("refreshToken", {
            "appType": app_type,
            "refreshToken": refresh_token,
            "terminalUUID": terminal_uuid
        })

    def register(self, cloud_password: str, email: str, locale: str, nickname: str, username: str):
        return self.send_request("register", {
            "cloudPassword": cloud_password,
            "email": email,
            "locale": locale,
            "nickname": nickname,
            "username": username
        })

    def register_with_verify_code(self, country: str, country_code: str, nickname: str, password: str, phone: str, verify_code: str):
        return self.send_request("registerWithVerifyCode", {
            "country": country,
            "countryCode": country_code,
            "nickname": nickname,
            "password": password,
            "phone": phone,
            "verifyCode": verify_code
        })

    def remove_device_user(self, device_id: str, owner_email: str, user_email: str):
        return self.send_request("removeDeviceUser", {
            "deviceId": device_id,
            "owner_email": owner_email,
            "user_email": user_email
        })

    def resend_reg_email(self, email: str, locale: str):
        return self.send_request("resendRegEmail", {
            "email": email,
            "locale": locale
        })

    def reset_password_with_verify_code(self, email: str, password: str, verify_code: str):
        return self.send_request("resetPasswordWithVerifyCode", {
            "email": email,
            "password": password,
            "verifyCode": verify_code
        })

    def set_alias(self, device_id: str, alias: str):
        return self.send_request("setAlias", {
            "deviceId": device_id,
            "alias": alias
        })

    def set_badge(self, badge: int):
        return self.send_request("setBadge", {
            "badge": badge
        })

    def subscribe_msg(self, subscribe_msg_type: list[str]):
        return self.send_request("subscribeMsg", {
            "subscribeMsgType": subscribe_msg_type
        })

    def transfer_device_ownership(self, device_id: str, old_owner_account: str, new_owner_account: str):
        return self.send_request("transferDeviceOwnership", {
            "deviceId": device_id,
            "oldOwnerAccount": old_owner_account,
            "newOwnerAccount": new_owner_account
        })

    def unbind_device(self, cloud_username: str, device_id: str):
        return self.send_request("unbindDevice", {
            "cloudUserName": cloud_username,
            "deviceId": device_id
        })

    def update_account_info(self, cloud_username: str, country_code: str, nickname: str):
        return self.send_request("updateAccountInfo", {
            "cloudUserName": cloud_username,
            "contryCode": country_code,
            "nickname": nickname
        })