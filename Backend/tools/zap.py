import time
from zapv2 import ZAPv2

MAX_RETRIES = 10
RETRY_DELAY_SECONDS = 5


def initialize_zap_scanner():
    """
    Initializes the ZAP scanner with retry logic.
    """
    for attempt in range(MAX_RETRIES):
        try:
            print(f"Attempt {attempt + 1}/{MAX_RETRIES}: Initializing ZAP scanner...")
            zap = ZAPv2(proxies={'http': 'http://zap:8080', 'https': 'http://zap:8080'})

            # 🔥 CRITICAL: Configure ZAP to NEVER use HTTPS
            try:
                print("🔧 Configuring ZAP for STRICT HTTP-only scanning...")

                # Create HTTP-only context
                context_name = 'http-only-context'
                context_id = zap.context.new_context(context_name)

                # 🔥 EXCLUDE ALL HTTPS - ABSOLUTELY NO EXCEPTIONS
                zap.context.exclude_from_context(context_name, 'https://.*')
                zap.context.exclude_from_context(context_name, '.*:443.*')

                print(f"✅ Created HTTP-only context ID: {context_id}")
                print("✅ EXCLUDED ALL HTTPS traffic")

                # Also disable SSL/TLS scanner plugins
                try:
                    # Disable SSL/TLS related scanners
                    zap.ascan.disable_scanners('40035,40036,40037')  # SSL/TLS scanners
                    print("✅ Disabled SSL/TLS scanners")
                except Exception as e:
                    print(f"⚠️  Could not disable SSL scanners: {e}")

            except Exception as config_error:
                print(f"⚠️  ZAP config warning: {config_error}")
                # Don't fail - keep going

            print("Successfully connected to ZAP API.")
            return zap

        except Exception as e:
            print(f"Failed to connect to ZAP API on attempt {attempt + 1}: {e}")
            if attempt < MAX_RETRIES - 1:
                print(f"Retrying in {RETRY_DELAY_SECONDS} seconds...")
                time.sleep(RETRY_DELAY_SECONDS)
            else:
                print("Max retries reached. Could not connect to ZAP.")
                raise ConnectionError("Failed to initialize ZAP scanner after multiple retries.")