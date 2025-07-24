import hmac
import hashlib
import json
import os
from flask import Flask, request, abort
import requests
import logging

GITHUB_WEBHOOK_SECRET = os.environ.get("GITHUB_WEBHOOK_SECRET")
SLACK_WEBHOOK_URL = os.environ.get("SLACK_WEBHOOK_URL")

app = Flask(__name__)

def verify_signature(data, signature):
    sha_name, signature = signature.split('=')
    if sha_name != 'sha256':
        return False
    secret = GITHUB_WEBHOOK_SECRET
    if not secret:
        return False
    expected_signature = hmac.new(secret.encode(), data, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected_signature, signature)

@app.route('/api/github-webhook', methods=['POST'])
def github_webhook():
    try:
        # Aquí tu lógica, por ejemplo:
        signature = request.headers.get('X-Hub-Signature-256')
        if not signature:
            abort(400, 'Missing signature')

        data = request.get_data()
        if not verify_signature(data, signature):
            abort(400, 'Invalid signature')

        event = request.headers.get('X-GitHub-Event')
        if event == 'pull_request':
            payload = request.json
            action = payload.get('action')

            if action == 'opened':
                pr = payload['pull_request']
                pr_title = pr['title']
                pr_url = pr['html_url']
                pr_user = pr['user']['login']
                repo_name = payload['repository']['name']


                slack_message = {
                    'text': f'🆕 New PR opened in {repo_name} by {pr_user}: *<{pr_url}|{pr_title}>*'
                }

                resp = requests.post(SLACK_WEBHOOK_URL, json=slack_message)
                if resp.status_code != 200:
                    app.logger.error(f'Error sending message to Slack: {resp.text}')
                    return 'Error sending message to Slack', 500
                return 'Message sent to Slack', 200
            
            if action == 'closed':
                pr = payload['pull_request']
                if pr.get('merged'):
                    pr_title = pr['title']
                    pr_url = pr['html_url']
                    pr_user = pr['user']['login']
                    repo_name = payload['repository']['name']

                    slack_message = {
                        'text': f'🔀 PR merged in {repo_name} by {pr_user}: *<{pr_url}|{pr_title}>*'
                    }

                    resp = requests.post(SLACK_WEBHOOK_URL, json=slack_message)
                    if resp.status_code != 200:
                        app.logger.error(f'Error sending message to Slack: {resp.text}')
                        return 'Error sending message to Slack', 500
                    return 'Message sent to Slack', 200
        
        return '', 204

    except Exception as e:
        app.logger.error(f'Exception handling webhook: {e}', exc_info=True)
        abort(500, 'Internal Server Error')