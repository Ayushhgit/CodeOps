"""GitHub webhook endpoints."""

from typing import Any

import structlog
from fastapi import APIRouter, Header, HTTPException, Request, status

from app.github.webhooks import webhook_processor

router = APIRouter()
logger = structlog.get_logger(__name__)


@router.post("/github")
async def github_webhook(
    request: Request,
    x_github_event: str = Header(..., alias="X-GitHub-Event"),
    x_github_delivery: str = Header(..., alias="X-GitHub-Delivery"),
    x_hub_signature_256: str = Header(None, alias="X-Hub-Signature-256"),
) -> dict[str, Any]:
    """
    Receive and process GitHub webhooks.

    Security:
    - Validates webhook signature
    - Logs all events for audit
    """
    # Get raw body for signature verification
    body = await request.body()

    # Verify signature
    if x_hub_signature_256:
        if not webhook_processor.verify_signature(body, x_hub_signature_256):
            logger.warning(
                "Invalid webhook signature",
                delivery_id=x_github_delivery,
                event=x_github_event,
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid webhook signature",
            )
    else:
        logger.warning(
            "Webhook received without signature",
            delivery_id=x_github_delivery,
            event=x_github_event,
        )

    # Parse payload
    try:
        raw_payload = await request.json()
    except Exception as e:
        logger.error("Failed to parse webhook payload", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid JSON payload",
        )

    # Parse and process
    payload = webhook_processor.parse_payload(
        event_type=x_github_event,
        delivery_id=x_github_delivery,
        raw_payload=raw_payload,
    )

    logger.info(
        "Processing webhook",
        event=payload.event.value,
        action=payload.action,
        delivery_id=x_github_delivery,
        repo=payload.repo_full_name,
    )

    # Process the webhook
    result = await webhook_processor.process(payload)

    return {
        "status": "processed",
        "delivery_id": x_github_delivery,
        "event": x_github_event,
        "handlers_executed": len(result.get("handlers_executed", [])),
        "errors": len(result.get("errors", [])),
    }
