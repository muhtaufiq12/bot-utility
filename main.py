from flask import Flask, request, jsonify, make_response
import requests
import hvac
import os
import string
import random

app = Flask(__name__)

# Authenticate to Vault
client = hvac.Client (
    url=os.environ['VAULT_URL'],
    token=os.environ['VAULT_TOKEN'],
)

# Stash Header
stash_headers = {
    "Authorization" : "Njg3MTc1NjU4MDA1OlfgPL6Tt7yNprW62ANs09Uvmnd+",
    "Content-Type"  : "application/json",
    "Accept"        : "application/json"
}

@app.route("/v1/approve", methods = ['POST'])
def approve():
    # Get request payload
    req = request.get_json()

    # Read Token from Vault
    read_response = client.secrets.kv.read_secret_version(path='bot-utility')
    token = read_response['data']['data']['token']
    print (token)

    # Checking Headers
    headers_json_type = request.headers.get('Content-Type')
    headers_token_type = request.headers.get('X-Api-Key')
    err_approvals = []
    if headers_json_type == "application/json":
        if headers_token_type != token:
            return make_response(jsonify(
                success=False,
                errors="Unauthorized Access",
            ), 403)
            
        for approval in req["approvals"]:
            # Write comment
            r = requests.post(approval["pr_url"] + "/comments", headers=stash_headers, json={"text": approval["comment"]})
            if r.status_code != requests.codes.created:
                err_approvals.append({
                    "pr_url": approval["pr_url"],
                    "step": "comment_pr",
                    "reason": r.text
                })
            # Approve pull request
            r = requests.post(approval["pr_url"] + "/approve", headers=stash_headers)
            if r.status_code != requests.codes.ok:
                err_approvals.append({
                    "pr_url": approval["pr_url"],
                    "step": "approve_pr",
                    "reason": r.text
                })
        if len(err_approvals) > 0:
            return make_response(jsonify(
                success=False,
                errors=err_approvals,
            ), 500)
        else:
            return make_response(jsonify(
                success=True,
                errors=err_approvals,
            ), 200)
    else:
        return make_response(jsonify(
            success=False,
            errors="Internal Server Error",
        ), 500)

@app.route("/v1/rotate-token")
def rotate_token():
    # Can only requested from localhost
    if request.remote_addr != "127.0.0.1":
        return make_response(jsonify(
            success=False,
            errors="Forbidden. Access only open from localhost",
        ), 403)
    # Generate random string
    string_length = 10
    letters = string.ascii_letters
    result_token = ''.join(random.choice(letters) for i in range(string_length))
    print (result_token)
    # Update token in vault
    create_response = client.secrets.kv.v2.create_or_update_secret(path='bot-utility', secret=dict(token = result_token))
    return make_response(jsonify(
        success=True,
        errors=[],
    ), 200)