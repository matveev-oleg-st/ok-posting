import requests
import hashlib
import json

ok_user_id         = ""
ok_group_id        = ""#ID группы gid
ok_app_id          = ""
ok_app_public_key  = ""#Публичный ключ приложения
ok_app_private_key = ""#Секретный ключ приложения
ok_access_token    = ""#Вечный токен
ok_redirect_url    = "https://discurs.info/login.html"

def ok_send_link_to_group(url):
    ok_session_secret_key = ""
    ok_format             = "json"
    ok_method             = 'mediatopic.post'
    ok_type               = "GROUP_THEME"
    ok_link_preview       = "true"

    ok_hash               = ok_access_token + ok_app_private_key    
    ok_secret_key         = hashlib.md5(ok_hash.encode('utf-8')).hexdigest()

    ok_json_data          = {"media":[{"type":"link","url":url}]}
    ok_attachment         = json.dumps(ok_json_data)

    ok_str_key            = 'application_key=' + ok_app_public_key + 'attachment=' + ok_attachment + 'format=' + ok_format + 'gid=' + ok_group_id + 'method=' + ok_method + 'text_link_preview=' + ok_link_preview + 'type=' + ok_type + ok_secret_key
    ok_sig                = hashlib.md5(ok_str_key.encode('utf-8')).hexdigest()
    
    ok_request_url        = 'https://api.ok.ru/fb.do?application_key=' + ok_app_public_key + '&attachment=' + ok_attachment + '&format=' + ok_format + '&gid=' + ok_group_id + '&method=' + ok_method + '&text_link_preview=' + ok_link_preview + '&type=' + ok_type + '&sig=' + ok_sig + '&access_token=' + ok_access_token
    
    ok_response           = requests.get(ok_request_url)
    print(ok_response.text)

def ok_send_link_to_user(url, ok_user_id_post):
    ok_session_secret_key = ""
    ok_format             = "json"
    ok_method             = 'mediatopic.post'
    ok_type               = "USER"
    ok_link_preview       = "true"

    ok_hash               = ok_access_token + ok_app_private_key    
    ok_secret_key         = hashlib.md5(ok_hash.encode('utf-8')).hexdigest()

    ok_json_data          = {"media":[{"type":"link","url":url}]}
    ok_attachment         = json.dumps(ok_json_data)

    ok_str_key            = 'application_key=' + ok_app_public_key + 'attachment=' + ok_attachment + 'format=' + ok_format + 'method=' + ok_method + 'text_link_preview=' + ok_link_preview + 'type=' + ok_type + ok_secret_key
    ok_sig                = hashlib.md5(ok_str_key.encode('utf-8')).hexdigest()
    
    ok_request_url        = 'https://api.ok.ru/fb.do?application_key=' + ok_app_public_key + '&attachment=' + ok_attachment + '&format=' + ok_format + '&gid=' + ok_group_id + '&method=' + ok_method + '&text_link_preview=' + ok_link_preview + '&type=' + ok_type + '&sig=' + ok_sig + '&access_token=' + ok_access_token
    
    ok_response           = requests.get(ok_request_url)
    print(ok_response.text)

def ok_get_auth_user_data(code):
    ok_url                = "https://api.ok.ru/oauth/token.do?code={}&client_id={}&client_secret={}&redirect_uri={}&grant_type=authorization_code".format(code, ok_app_id, ok_app_private_key, ok_redirect_url)
    ok_response           = requests.post(ok_url)
    ok_response_json      = ok_response.json()
    if ok_response_json["access_token"]:
        ok_token          = ok_response_json["access_token"]
        ok_hash           = ok_token + ok_app_private_key
        ok_secret_key     = hashlib.md5(ok_hash.encode('utf-8')).hexdigest()
        ok_str_key        = 'application_key=COOHOBKGDIHBABABAfields=UID,NAMEformat=jsonmethod=users.getCurrentUser' + ok_secret_key
        ok_sig            = hashlib.md5(ok_str_key.encode('utf-8')).hexdigest()
        ok_url_data       = 'https://api.ok.ru/fb.do?application_key=' + ok_app_public_key + '&fields=UID%2CNAME&format=json&method=users.getCurrentUser&sig=' + ok_sig + '&access_token=' + ok_token
        ok_data           = requests.get(ok_url_data)
        ok_data_json      = ok_data.json()
        return {'type': 'message','okid': ok_data_json['uid'],'name': ok_data_json['name']}
    else:
        if ok_response_json["error_description"]:
            return {'type': 'error', 'message': ok_response_json["error_description"]}
        else:
            return {'type': 'error', 'message': 'ошибка...'}
