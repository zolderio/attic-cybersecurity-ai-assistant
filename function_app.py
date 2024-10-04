import azure.functions as func
import logging, json
import os, requests, uuid
from azure.data.tables import TableClient, UpdateMode
from azure.core.exceptions import ResourceNotFoundError
from openai import OpenAI

# Global vars
app = func.FunctionApp(http_auth_level=func.AuthLevel.ANONYMOUS)
whoami = os.environ["ENVIRONMENT"]

# OpenAI vars
OpenAI.api_key = os.environ["OPENAI_API_KEY"]
client = OpenAI()

# Zendesk vars
zendesk_domain = os.environ["ZENDESK_DOMAIN"]
api_token = os.environ["ZENDESK_API_TOKEN"]
email = ''

# Database connections
connection_string = os.environ['TABLE_CONNECTION_STRING']
table_client_tickets = TableClient.from_connection_string(connection_string, f'tickets{whoami}')
table_client_comments = TableClient.from_connection_string(connection_string, f'comments{whoami}')
table_client_customers = TableClient.from_connection_string(connection_string, f'aienabled{whoami}')

# Triggers on a Comment
def storeIncidentInfo(ticket_id):
    createTicket(ticket_id)
    ticket = table_client_tickets.get_entity(partition_key='tickets', row_key=ticket_id)    
    return ticket

# Creates the ticket
def createTicket(ticket_id):
    url = f"https://{zendesk_domain}.zendesk.com/api/v2/tickets/{ticket_id}"
    response = requests.get(url, auth=(f'{email}/token', api_token))

    if response.status_code != 200:
        logging.error(f'createTicket Zendesk failed with status code: {response.status_code}')
        postTeamsDebugging(f"createTicket Zendesk failed with error code {response.status_code}")
        return None
    
    entity = {
        'PartitionKey': 'tickets',
        'RowKey': ticket_id,
        'ticket_id': ticket_id,
        'ticket_title': response.json()['ticket']['subject'],
        'first_comment': response.json()['ticket']['description'],
        'second_comment': getSecondComment(ticket_id),
        'external_context': getExternalContext(response.json()['ticket']['subject']),
        'thread_created': False,
        'ready': True      
    }
    table_client_tickets.create_entity(entity=entity)
    return

# Retrieves the second comment of a ticket
def getSecondComment(ticket_id):
    url = f"https://{zendesk_domain}.zendesk.com/api/v2/tickets/{ticket_id}/comments"
    response = requests.get(url, auth=(f'{email}/token', api_token))

    if response.status_code != 200:
        logging.error(f'getSecondComment Zendesk failed with status code: {response.status_code}')
        postTeamsDebugging(f"getSecondComment Zendesk failed with error code {response.status_code}")
        return None

    comments_data = response.json()
    if 'comments' in comments_data and len(comments_data['comments']) >= 2:
        second_comment = comments_data['comments'][1]
        return second_comment["body"]
    else:
        return None

# Retrieves the external context of a ticket
def getExternalContext(ticket_title):
    url = "https://<URL>/api/QueryData"
    secret = os.environ["AICONTEXT_SECRET"]
    params = {'title': ticket_title, 'secret': secret}

    response = requests.get(url, params=params)

    if response.status_code != 200:
        logging.error(f'getExternalContext failed with status code: {response.status_code}')
        postTeamsDebugging(f"getExternalContext failed with error code {response.status_code}")
        return None

    data = response.json()
    return data.get('code', 'None')

# Get the organization ID of the latest comment on a ticket
def getLatestCommentOrgId(ticket_id):
    # Retrieve the latest comment of a ticket
    comments_url = f"https://{zendesk_domain}.zendesk.com/api/v2/tickets/{ticket_id}/comments"
    comments_response = requests.get(comments_url, auth=(f'{email}/token', api_token))

    if comments_response.status_code != 200:
        logging.error(f'getLatestCommentOrgId / comments_response failed with status code: {comments_response.status_code}')
        postTeamsDebugging(f"getLatestCommentOrgId / comments_response failed with error code {comments_response.status_code}")
        return None, None

    comments_data = comments_response.json()
    if 'comments' in comments_data and comments_data['comments']:
        latest_comment = comments_data['comments'][-1]  # Get the last comment
        author_id = latest_comment["author_id"]

        # Retrieve the user's details to get the organization_id
        user_url = f"https://{zendesk_domain}.zendesk.com/api/v2/users/{author_id}"
        user_response = requests.get(user_url, auth=(f'{email}/token', api_token))

        if user_response.status_code != 200:
            logging.error(f'getLatestCommentOrgId / user_response failed with status code: {comments_response.status_code}')
            postTeamsDebugging(f"getLatestCommentOrgId / user_response failed with error code {comments_response.status_code}")
            return latest_comment["body"], None

        user_data = user_response.json()
        organization_id = user_data["user"].get("organization_id")

        return organization_id
    else:
        return None

# Get the organization ID of the latest comment on a ticket
def getTicketOrgIdAndName(ticket_id):
    ticket_url = f"https://{zendesk_domain}.zendesk.com/api/v2/tickets/{ticket_id}"
    ticket_response = requests.get(ticket_url, auth=(f'{email}/token', api_token))

    if ticket_response.status_code != 200:
        logging.error(f'getTicketOrgIdAndName / ticket_response failed with status code: {ticket_response.status_code}')
        postTeamsDebugging(f"getTicketOrgIdAndName / ticket_response failed with error code {ticket_response.status_code}")
        return None

    ticket_data = ticket_response.json()
    requester_id = ticket_data["ticket"]["requester_id"]

    # Retrieve the user's details to get the organization_id
    user_url = f"https://{zendesk_domain}.zendesk.com/api/v2/users/{requester_id}"
    user_response = requests.get(user_url, auth=(f'{email}/token', api_token))

    if user_response.status_code != 200:
        logging.error(f'getTicketOrgIdAndName / user_response failed with status code: {ticket_response.status_code}')
        postTeamsDebugging(f"getTicketOrgIdAndName / user_response failed with error code {ticket_response.status_code}")
        return None

    user_data = user_response.json()
    organization_id = user_data["user"].get("organization_id")

    # Retrieve the organization's details to get the organization_name
    org_url = f"https://{zendesk_domain}.zendesk.com/api/v2/organizations/{organization_id}"
    org_response = requests.get(org_url, auth=(f'{email}/token', api_token))

    if org_response.status_code != 200:
        logging.error(f'getTicketOrgIdAndName / org_response failed with status code: {ticket_response.status_code}')
        postTeamsDebugging(f"getTicketOrgIdAndName / org_response failed with error code {ticket_response.status_code}")
        return None

    org_data = org_response.json()
    organization_name = org_data["organization"].get("name")

    return organization_id, organization_name

# Get the unique ID of the latest comment
def getLatestCommentId(ticket_id):
    # Retrieve the latest comment of a ticket
    comments_url = f"https://{zendesk_domain}.zendesk.com/api/v2/tickets/{ticket_id}/comments"
    comments_response = requests.get(comments_url, auth=(f'{email}/token', api_token))

    if comments_response.status_code != 200:
        logging.error(f'getLatestCommentId failed with status code: {comments_response.status_code}')
        postTeamsDebugging(f"getLatestCommentId failed with error code {comments_response.status_code}")
        return None, None

    comments_data = comments_response.json()
    if 'comments' in comments_data and comments_data['comments']:
        latest_comment = comments_data['comments'][-1]  # Get the last comment
        comment_id = latest_comment["id"]

        return comment_id
    else:
        return None

# Initiate the ChatGPT chat on first customer comment
def initiateChatGPT(ticket, comment):
    try:
        thread = client.beta.threads.create()
        client.beta.threads.messages.create(
            thread_id=thread.id,
            role="assistant",
            content=(
                f"{ticket['ticket_title']} || {ticket['first_comment']} || {ticket['second_comment']} || {ticket['external_context']}"
            )
        )

        client.beta.threads.messages.create(
            thread_id=thread.id,
            role="user",
            content=comment
        )

        client.beta.threads.runs.create_and_poll(
            thread_id=thread.id,
            assistant_id="<ASSISTANT_ID>"
        )

        messages = client.beta.threads.messages.list(thread_id=thread.id)
        logging.info(messages)
        latest_message = messages.data[0]
        latest_message_content = latest_message.content[0].text.value

        ticket["thread_created"] = True
        ticket["thread_id"] = thread.id
        table_client_tickets.update_entity(mode=UpdateMode.REPLACE, entity=ticket)

        return latest_message_content
    except Exception as e:
        logging.error(f'initiateChatGPT failed with status code: {e}')
        postTeamsDebugging(f"initiateChatGPT failed with error code {e}")
        return None

def appendChatGPT(ticket, comment):
    try:
        ticket = table_client_tickets.get_entity(partition_key='tickets', row_key=ticket["ticket_id"]) 

        client.beta.threads.messages.create(
            thread_id=ticket["thread_id"],
            role="user",
            content=comment
        )

        client.beta.threads.runs.create_and_poll(
            thread_id=ticket["thread_id"],
            assistant_id="<ASSISTANT_ID>"
        )

        messages = client.beta.threads.messages.list(thread_id=ticket["thread_id"])
        logging.info(messages)
        latest_message = messages.data[0]
        latest_message_content = latest_message.content[0].text.value

        logging.info(latest_message_content)

        return latest_message_content
    except Exception as e:
        logging.error(f'appendChatGPT failed with status code: {e}')
        postTeamsDebugging(f"appendChatGPT failed with error code {e}")
        return None

# Write a comment to the queue
def writeComment(ticket, openai_response, question, org_name):
        uid = str(uuid.uuid4())
        comment_id = str(getLatestCommentId(ticket["ticket_id"]))

        query = table_client_comments.query_entities(query_filter="comment_id eq @comment_id", parameters={'comment_id': comment_id})
        query_results = list(query)
        
        if len(query_results) > 0:
            logging.info(f"Comment with comment_id {comment_id} already exists. Not adding a new comment.")
            return

        entity = {
            'PartitionKey': 'comments',
            'RowKey': uid,
            'comment_id': comment_id,
            'ticket_id': str(ticket["ticket_id"]),
            'customer_question': question,
            'message': openai_response,
            'review_conclusion': False,
            'sent': False
        }

        table_client_comments.create_entity(entity=entity)
        postTeamsNotification(question, openai_response, uid, str(ticket["ticket_id"]), org_name)
        return

# If the message is enable AI, then write it to the table
def isAiEnabledMessage(comment, submitter):
    if comment == "Check Attic AI Assistant (beta) is now okay" or comment == "Check Attic AI Assistant (beta) is nu in orde":
        entity = {
            'PartitionKey': 'customers',
            'RowKey': str(submitter),
            'organization_id': str(submitter)
        }

        table_client_customers.create_entity(entity=entity)
        return True
    else:
        return False

# Check if AI is enabled
def isAiEnabled(customer_id):
    try:
        table_client_customers.get_entity(partition_key='customers', row_key=customer_id)
        return True
    except:
        return False

def postTeamsNotification(question, answer, comment_id, ticket_id, org_name):
    message = {
        "type": "AdaptiveCard",
        "version": "1.0",
        "body": [
            {
                "type": "TextBlock",
                "text": f"Generated AI Message",
                "weight": "Bolder",
                "size": "Medium"
            },
            {
                "type": "FactSet",
                "facts": [
                    {"title": "Organization:", "value": org_name},
                    {"title": "Customer question:", "value": question},
                    {"title": "AI Reply:", "value": answer}
                ]
            },
            {
                "type": "ActionSet",
                "actions": [
                    {
                        "type": "Action.OpenUrl",
                        "title": "Send",
                        "url": f"https://<URL>/api/review?id={comment_id}&valid=True"
                    },
                    {
                        "type": "Action.OpenUrl",
                        "title": "Open incident",
                        "url": f"https://<URL>/agent/tickets/{ticket_id}"
                    }
                ]
            }
        ]
    }

    data = {
        "type": "message",
        "attachments": [
            {
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": message
            }
        ]
    }

    headers = { 'Content-Type': 'application/json' }
    requests.post(os.environ["TEAMS_WEBHOOK"], headers=headers, data=json.dumps(data))
    return

# Post a debugging message to teams
def postTeamsDebugging(message):
    card = {
        "type": "AdaptiveCard",
        "body": [
            {
                "type": "Container",
                "style": "emphasis",
                "items": [
                    {
                        "type": "ColumnSet",
                        "columns": [
                            {
                                "type": "Column",
                                "width": "auto",
                                "items": [
                                    {
                                        "type": "TextBlock",
                                        "text": f"Debugging",
                                        "wrap": True,
                                        "size": "large",
                                        "color": "warning",
                                        "isSubtle": True,
                                        "weight": "bolder"
                                    }
                                ]
                            }
                        ]
                    }
                ]
            },
            {
                "type": "Container",
                "items": [
                    {
                        "type": "TextBlock",
                        "text": f"{message}",
                        "wrap": True
                    }
                ]
            }
        ],
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
        "version": "1.0"
    }
    
    payload = {
        "type": "message",
        "attachments": [
            {
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": card
            }
        ]
    }
    
    headers = { 'Content-Type': 'application/json' }
    requests.post(os.environ["TEAMS_WEBHOOK"], headers=headers, data=json.dumps(payload))
    return

def addComment(ticket_id, message, sent):
    if not sent:
        auth = (f'{email}/token', api_token)
        url = f'https://{zendesk_domain}.zendesk.com/api/v2/tickets/{ticket_id}.json'
        
        data = {
            "ticket": {
                "comment": {
                    "body": message
                },
                "status": "pending"
            }
        }
        
        headers = {
            'Content-Type': 'application/json'
        }
        
        response = requests.put(url, json=data, auth=auth, headers=headers)
        if response.status_code == 200:
            logging.info("Comment added successfully.")
            return True
        else:
            logging.error(f'addComment Zendesk failed with status code: {response.status_code}')
            postTeamsDebugging(f"addComment Zendesk failed with error code {response.status_code}")
            return False
    else:
        return False

# Webhook function
@app.route(route="webhook")
def webhook(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Received a webhook request.')

    x_secret = req.headers.get('X-Secret')
    if x_secret != os.environ.get('SECRET'):
        return func.HttpResponse(
             "Invalid auth header",
             status_code=403
        )

    try:
        req_body = req.get_json()
    except ValueError:
        return func.HttpResponse(
             "Invalid JSON received",
             status_code=400
        )

    action = req_body.get('event')

    if action == "update":
        try:
            ticket = table_client_tickets.get_entity(partition_key='tickets', row_key=req_body.get("ticket_id"))   
        except ResourceNotFoundError:
            ticket = storeIncidentInfo(req_body.get("ticket_id"))

        submitter = getLatestCommentOrgId(ticket["ticket_id"])
        ticket_org, org_name = getTicketOrgIdAndName(ticket["ticket_id"])

        if isAiEnabledMessage(req_body.get("comment"), ticket_org):
            pass
        elif (str(submitter) != str(os.environ["ATTIC_AGENT_ORGANIZATION"]) and 
              ticket['ready'] and 
              not ticket['thread_created'] and 
              isAiEnabled(str(submitter))):
            openai_response = initiateChatGPT(ticket, req_body.get("comment"))
            writeComment(ticket, openai_response, req_body.get("comment"), org_name)
        elif (str(submitter) != str(os.environ["ATTIC_AGENT_ORGANIZATION"]) and
              ticket['ready'] and 
              ticket['thread_created'] and 
              isAiEnabled(str(submitter))):
            openai_response = appendChatGPT(ticket, req_body.get("comment"))
            writeComment(ticket, openai_response, req_body.get("comment"), org_name)

    return func.HttpResponse("OK", status_code=200)

@app.route(route="review", auth_level=func.AuthLevel.ANONYMOUS)
def review(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Review endpoint executed')

    id = req.params.get('id')
    valid = req.params.get('valid')

    if id and valid:
        comment_row = table_client_comments.get_entity(partition_key='comments', row_key=id)
        ticket_id = comment_row["ticket_id"]
        comment = comment_row["message"]
        result = addComment(ticket_id, comment, comment_row["sent"])

        comment_row["review_conclusion"] = True
        comment_row["sent"] = True
        table_client_comments.update_entity(mode=UpdateMode.REPLACE, entity=comment_row)

        if result:
            return func.HttpResponse(f"OK")
        else:
            return func.HttpResponse(f"OK")
    else:
        return func.HttpResponse(f"Invalid id or valid")