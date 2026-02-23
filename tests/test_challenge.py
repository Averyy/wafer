"""Tests for challenge detection."""

from wafer._challenge import ChallengeType, detect_challenge

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _h(**kw) -> dict[str, str]:
    """Build a headers dict with lowercase keys."""
    return {k.lower().replace("_", "-"): v for k, v in kw.items()}


# ---------------------------------------------------------------------------
# Cloudflare
# ---------------------------------------------------------------------------


class TestCloudflare:
    def test_cf_mitigated_header(self):
        headers = _h(cf_mitigated="challenge")
        assert detect_challenge(403, headers, "") == ChallengeType.CLOUDFLARE

    def test_cf_mitigated_header_any_status(self):
        headers = _h(cf_mitigated="challenge")
        assert detect_challenge(200, headers, "") == ChallengeType.CLOUDFLARE

    def test_cf_chl_opt_body_marker(self):
        body = '<html><script>window._cf_chl_opt={}</script></html>'
        assert detect_challenge(403, {}, body) == ChallengeType.CLOUDFLARE

    def test_cf_chl_ctx_body_marker(self):
        body = '<html><script>var _cf_chl_ctx = {}</script></html>'
        assert detect_challenge(403, {}, body) == ChallengeType.CLOUDFLARE

    def test_challenge_form_body_marker(self):
        body = (
            '<html><form id="challenge-form"'
            ' action="/cdn-cgi/challenge-platform">'
            "</form></html>"
        )
        assert detect_challenge(403, {}, body) == ChallengeType.CLOUDFLARE

    def test_cf_body_markers_on_503(self):
        """CF body markers should also trigger on 503."""
        body = '<html><script>window._cf_chl_opt={}</script></html>'
        assert detect_challenge(503, {}, body) == ChallengeType.CLOUDFLARE

    def test_cf_body_markers_only_on_403_503(self):
        """CF body markers should not trigger on 200."""
        body = '<html><script>window._cf_chl_opt={}</script></html>'
        assert detect_challenge(200, {}, body) is None

    def test_cf_mitigated_not_challenge(self):
        """cf-mitigated with value other than 'challenge' should not match."""
        headers = _h(cf_mitigated="captcha")
        assert detect_challenge(403, headers, "") != ChallengeType.CLOUDFLARE


# ---------------------------------------------------------------------------
# Akamai
# ---------------------------------------------------------------------------


class TestAkamai:
    def test_abck_cookie_403(self):
        headers = _h(set_cookie="_abck=abc123; Path=/")
        assert detect_challenge(403, headers, "") == ChallengeType.AKAMAI

    def test_ak_bmsc_cookie_403(self):
        headers = _h(set_cookie="ak_bmsc=abc123; Path=/")
        assert detect_challenge(403, headers, "") == ChallengeType.AKAMAI

    def test_abck_cookie_non_403_with_body_markers(self):
        headers = _h(set_cookie="_abck=abc123; Path=/")
        body = '<script>var bmSz = "abc";</script>'
        assert detect_challenge(429, headers, body) == ChallengeType.AKAMAI

    def test_abck_cookie_200_small_behavioral(self):
        headers = _h(set_cookie="_abck=abc123; Path=/")
        body = '<div class="sec-if-cpt">Please verify</div>'
        assert detect_challenge(200, headers, body) == ChallengeType.AKAMAI

    def test_abck_cookie_200_large_body_not_challenge(self):
        """Large 200 response with _abck is normal content, not a challenge."""
        headers = _h(set_cookie="_abck=abc123; Path=/")
        body = "x" * 50_000
        assert detect_challenge(200, headers, body) is None

    def test_akamai_body_marker_403(self):
        body = '<html><body>Akamai Bot Manager</body></html>'
        assert detect_challenge(403, {}, body) == ChallengeType.AKAMAI

    def test_akam_body_marker_403(self):
        body = '<html><body>Reference: akam-12345</body></html>'
        assert detect_challenge(403, {}, body) == ChallengeType.AKAMAI

    def test_bazadebezolkohpepadr_is_akamai_not_shape(self):
        """bazadebezolkohpepadr is Akamai Bot Manager, not F5 Shape."""
        body = '<script>bazadebezolkohpepadr="1070367992"</script>'
        assert detect_challenge(403, {}, body) == ChallengeType.AKAMAI


# ---------------------------------------------------------------------------
# F5 Shape
# ---------------------------------------------------------------------------


class TestShape:
    def test_istlwashere_body_200(self):
        """Shape interstitial: 200 + istlWasHere in body."""
        body = '<html><head></head><body>istlWasHere</body></html>'
        assert detect_challenge(200, {}, body) == ChallengeType.SHAPE

    def test_istlwashere_case_insensitive(self):
        """istlWasHere detection is case-insensitive."""
        body = '<html><body>IstlWasHere</body></html>'
        assert detect_challenge(200, {}, body) == ChallengeType.SHAPE

    def test_imp_apg_r_body(self):
        """_imp_apg_r_ resource path in body."""
        body = '<script src="/_imp_apg_r_/js/loader.js"></script>'
        assert detect_challenge(200, {}, body) == ChallengeType.SHAPE

    def test_large_body_with_istlwashere_still_detected(self):
        """Shape interstitials are JS-heavy — no size limit on body check."""
        body = "x" * 60_000 + "istlWasHere" + "y" * 10_000
        assert detect_challenge(200, {}, body) == ChallengeType.SHAPE

    def test_200_without_shape_markers_not_challenge(self):
        """Normal 200 page is not Shape."""
        body = "<html><body>Welcome to our store</body></html>"
        assert detect_challenge(200, {}, body) is None


# ---------------------------------------------------------------------------
# DataDome
# ---------------------------------------------------------------------------


class TestDataDome:
    def test_datadome_cookie_403(self):
        headers = _h(set_cookie="datadome=abc123; Path=/")
        assert detect_challenge(403, headers, "") == ChallengeType.DATADOME

    def test_datadome_cookie_200_not_challenge(self):
        """datadome cookie on 200 is normal tracking, not a challenge."""
        headers = _h(set_cookie="datadome=abc123; Path=/")
        assert detect_challenge(200, headers, "") is None

    def test_datadome_body_marker_403(self):
        body = '<script src="https://js.datadome.co/tags.js"></script>'
        assert detect_challenge(403, {}, body) == ChallengeType.DATADOME

    def test_dd_js_body_marker_403(self):
        body = '<script src="/dd.js"></script>'
        assert detect_challenge(403, {}, body) == ChallengeType.DATADOME

    def test_datadome_cookie_429(self):
        """datadome cookie + 429 should be detected as DataDome."""
        headers = _h(set_cookie="datadome=abc123; Path=/")
        assert detect_challenge(429, headers, "") == ChallengeType.DATADOME

    def test_datadome_body_marker_429(self):
        """DataDome body markers on 429 should be detected."""
        body = '<script src="https://js.datadome.co/tags.js"></script>'
        assert detect_challenge(429, {}, body) == ChallengeType.DATADOME

    def test_plain_429_without_datadome_not_detected(self):
        """Plain 429 without datadome markers is not DataDome."""
        assert detect_challenge(429, {}, "") is None


# ---------------------------------------------------------------------------
# PerimeterX / HUMAN
# ---------------------------------------------------------------------------


class TestPerimeterX:
    def test_px3_cookie_403(self):
        headers = _h(set_cookie="_px3=abc; Path=/")
        assert detect_challenge(403, headers, "") == ChallengeType.PERIMETERX

    def test_pxhd_cookie_429(self):
        headers = _h(set_cookie="_pxhd=abc; Path=/")
        assert detect_challenge(429, headers, "") == ChallengeType.PERIMETERX

    def test_px_body_marker_403(self):
        body = '<div id="px-captcha">Press and hold</div>'
        assert detect_challenge(403, {}, body) == ChallengeType.PERIMETERX

    def test_human_security_body_marker(self):
        body = '<script src="https://client.human.security/px.js"></script>'
        assert detect_challenge(403, {}, body) == ChallengeType.PERIMETERX

    def test_press_hold_body_marker(self):
        body = '<p>Press & Hold to confirm you are not a bot</p>'
        assert detect_challenge(403, {}, body) == ChallengeType.PERIMETERX

    def test_px_cookie_200_not_challenge(self):
        """PX cookie on 200 is normal, not a challenge."""
        headers = _h(set_cookie="_px3=abc; Path=/")
        assert detect_challenge(200, headers, "") is None


# ---------------------------------------------------------------------------
# Imperva / Incapsula
# ---------------------------------------------------------------------------


class TestImperva:
    def test_reese84_cookie_403(self):
        headers = _h(set_cookie="reese84=abc; Path=/")
        assert detect_challenge(403, headers, "") == ChallengeType.IMPERVA

    def test_utmvc_cookie_403(self):
        headers = _h(set_cookie="___utmvc=abc; Path=/")
        assert detect_challenge(403, headers, "") == ChallengeType.IMPERVA

    def test_incapsula_body_marker(self):
        body = '<html><body>Incapsula incident ID: 12345</body></html>'
        assert detect_challenge(403, {}, body) == ChallengeType.IMPERVA

    def test_imperva_body_marker(self):
        body = '<html><body>Powered by Imperva</body></html>'
        assert detect_challenge(403, {}, body) == ChallengeType.IMPERVA

    def test_reese84_cookie_200_not_challenge(self):
        """reese84 on 200 is normal, not a challenge."""
        headers = _h(set_cookie="reese84=abc; Path=/")
        assert detect_challenge(200, headers, "") is None

    def test_x_cdn_incapsula_403(self):
        """x-cdn: Incapsula header on 403 identifies Imperva."""
        headers = {"x-cdn": "Incapsula"}
        assert detect_challenge(403, headers, "") == ChallengeType.IMPERVA

    def test_x_cdn_imperva_403(self):
        """x-cdn: Imperva header on 403 identifies Imperva."""
        headers = {"x-cdn": "Imperva"}
        assert detect_challenge(403, headers, "") == ChallengeType.IMPERVA

    def test_incapsula_resource_interstitial(self):
        """Imperva interstitial with _Incapsula_Resource on 200."""
        body = (
            '<html><head>'
            '<meta name="robots" content="noindex, nofollow"></head>'
            '<body><script src="/_Incapsula_Resource?SWJIYLWA=..."></script>'
            '</body></html>'
        )
        assert detect_challenge(200, {}, body) == ChallengeType.IMPERVA

    def test_x_cdn_incapsula_429(self):
        """x-cdn: Incapsula header on 429 identifies Imperva."""
        headers = {"x-cdn": "Incapsula"}
        assert detect_challenge(429, headers, "") == ChallengeType.IMPERVA

    def test_incapsula_resource_tiny_interstitial(self):
        """Tiny 200 page with _Incapsula_Resource is Imperva interstitial."""
        body = (
            '<html><head><script type="text/javascript"'
            ' src="/_Incapsula_Resource?SWJIYLWA=719d34d31c8e3a6e6fffd425f7e032f3">'
            '</script></head><body></body></html>'
        )
        assert detect_challenge(200, {}, body) == ChallengeType.IMPERVA

    def test_x_cdn_imperva_200_tiny_script_no_incapsula(self):
        """x-cdn: Imperva + tiny 200 WITHOUT _Incapsula_Resource is NOT
        detected — real Imperva-CDN pages have x-cdn too."""
        headers = {"x-cdn": "Imperva"}
        body = '<html><head><script src="/some-js"></script></head></html>'
        assert detect_challenge(200, headers, body) is None

    def test_incapsula_resource_large_body_not_challenge(self):
        """Large page mentioning _Incapsula_Resource is not a challenge."""
        body = (
            '<html><body>Article about _Incapsula_Resource...'
            + 'x' * 10_000
            + '</body></html>'
        )
        assert detect_challenge(200, {}, body) is None

    def test_x_cdn_imperva_200_large_body_not_challenge(self):
        """x-cdn: Imperva on large 200 page is real content."""
        headers = {"x-cdn": "Imperva"}
        body = '<html><head><script src="/app.js"></script></head>' + 'x' * 10_000
        assert detect_challenge(200, headers, body) is None


# ---------------------------------------------------------------------------
# Kasada
# ---------------------------------------------------------------------------


class TestKasada:
    def test_kpsdk_header_429(self):
        headers = {"x-kpsdk-ct": "some-value"}
        assert detect_challenge(429, headers, "") == ChallengeType.KASADA

    def test_kpsdk_cd_header_429(self):
        headers = {"x-kpsdk-cd": "some-value"}
        assert detect_challenge(429, headers, "") == ChallengeType.KASADA

    def test_kpsdk_header_403_not_kasada(self):
        """Kasada detection only on 429, not 403."""
        headers = {"x-kpsdk-ct": "some-value"}
        assert detect_challenge(403, headers, "") != ChallengeType.KASADA

    def test_kasada_body_ips_js(self):
        """Body with ips.js on 429 detects Kasada."""
        body = '<script src="/ips.js"></script>'
        assert detect_challenge(429, {}, body) == ChallengeType.KASADA

    def test_kasada_body_kpsdk(self):
        """Body with kpsdk marker on 429 detects Kasada."""
        body = '<html><script>KPSDK.configure({});</script></html>'
        assert detect_challenge(429, {}, body) == ChallengeType.KASADA

    def test_kasada_body_pjs(self):
        """Body with /p.js on 429 detects Kasada."""
        body = '<script src="/a1b2c3d4/e5f6g7h8/p.js"></script>'
        assert detect_challenge(429, {}, body) == ChallengeType.KASADA

    def test_kasada_in_js_only_challenges(self):
        """KASADA should be in JS_ONLY_CHALLENGES frozenset."""
        from wafer._challenge import JS_ONLY_CHALLENGES
        assert ChallengeType.KASADA in JS_ONLY_CHALLENGES


# ---------------------------------------------------------------------------
# AWS WAF
# ---------------------------------------------------------------------------


class TestAWSWAF:
    def test_amzn_waf_action_captcha_header(self):
        headers = {"x-amzn-waf-action": "captcha"}
        assert (
            detect_challenge(405, headers, "")
            == ChallengeType.AWSWAF
        )

    def test_amzn_waf_action_challenge_header(self):
        headers = {"x-amzn-waf-action": "challenge"}
        assert (
            detect_challenge(403, headers, "")
            == ChallengeType.AWSWAF
        )

    def test_aws_waf_token_cookie_403(self):
        headers = _h(
            set_cookie="aws-waf-token=abc123; Path=/"
        )
        assert (
            detect_challenge(403, headers, "")
            == ChallengeType.AWSWAF
        )

    def test_aws_waf_token_cookie_405(self):
        headers = _h(
            set_cookie="aws-waf-token=abc123; Path=/"
        )
        assert (
            detect_challenge(405, headers, "")
            == ChallengeType.AWSWAF
        )

    def test_aws_waf_token_cookie_202(self):
        """AWS WAF JS challenge returns 202."""
        headers = _h(
            set_cookie="aws-waf-token=abc123; Path=/"
        )
        assert (
            detect_challenge(202, headers, "")
            == ChallengeType.AWSWAF
        )

    def test_aws_waf_202_gokuprops_body(self):
        """AWS WAF 202 with gokuProps JS challenge SDK."""
        body = (
            '<script>window.gokuProps = {'
            '"key":"AQIDAHj..."}</script>'
        )
        assert (
            detect_challenge(202, {}, body)
            == ChallengeType.AWSWAF
        )

    def test_aws_waf_202_cookie_domain_list(self):
        """AWS WAF 202 with awsWafCookieDomainList."""
        body = (
            "<script>window.awsWafCookieDomainList"
            " = ['example.com'];</script>"
        )
        assert (
            detect_challenge(202, {}, body)
            == ChallengeType.AWSWAF
        )

    def test_aws_waf_body_marker_403(self):
        body = '<script src="awsWafJsChallenge.js"></script>'
        assert (
            detect_challenge(403, {}, body)
            == ChallengeType.AWSWAF
        )

    def test_aws_waf_token_cookie_200_not_challenge(self):
        """aws-waf-token on 200 is normal, not a challenge."""
        headers = _h(
            set_cookie="aws-waf-token=abc123; Path=/"
        )
        assert detect_challenge(200, headers, "") is None

    def test_amzn_waf_action_none_not_challenge(self):
        """x-amzn-waf-action with value 'allow' is not a challenge."""
        headers = {"x-amzn-waf-action": "allow"}
        assert detect_challenge(200, headers, "") is None


# ---------------------------------------------------------------------------
# Vercel
# ---------------------------------------------------------------------------


class TestVercel:
    def test_vercel_mitigated_challenge_header(self):
        headers = {"x-vercel-mitigated": "challenge"}
        assert (
            detect_challenge(429, headers, "")
            == ChallengeType.VERCEL
        )

    def test_vercel_mitigated_any_status(self):
        """Vercel header should trigger on any status."""
        headers = {"x-vercel-mitigated": "challenge"}
        assert (
            detect_challenge(200, headers, "")
            == ChallengeType.VERCEL
        )

    def test_vercel_mitigated_not_challenge(self):
        """x-vercel-mitigated with other values is not a challenge."""
        headers = {"x-vercel-mitigated": "blocked"}
        assert (
            detect_challenge(429, headers, "")
            != ChallengeType.VERCEL
        )


# ---------------------------------------------------------------------------
# ACW (Alibaba Cloud WAF)
# ---------------------------------------------------------------------------


class TestACW:
    def test_acw_challenge(self):
        body = "<script>var arg1='abcdef1234'; acw_sc__v2('test');</script>"
        assert detect_challenge(200, {}, body) == ChallengeType.ACW

    def test_acw_requires_both_markers(self):
        """Must have both acw_sc__v2 AND arg1."""
        body = "<script>acw_sc__v2('test');</script>"
        assert detect_challenge(200, {}, body) is None

    def test_acw_arg1_only(self):
        body = "<script>var arg1='abcdef1234';</script>"
        assert detect_challenge(200, {}, body) is None


# ---------------------------------------------------------------------------
# TMD (Alibaba)
# ---------------------------------------------------------------------------


class TestTMD:
    def test_tmd_punish_page(self):
        body = (
            '<html><meta http-equiv="refresh"'
            ' content="0;url=/_____tmd_____/punish?x=1">'
            "</html>"
        )
        assert detect_challenge(200, {}, body) == ChallengeType.TMD

    def test_tmd_only_on_200(self):
        """TMD detection only on 200 status."""
        body = '<html>/_____tmd_____/punish</html>'
        # On 403 it should fall through to generic_js if there's a script tag
        assert detect_challenge(200, {}, body) == ChallengeType.TMD


# ---------------------------------------------------------------------------
# Amazon
# ---------------------------------------------------------------------------


class TestAmazon:
    def test_amazon_captcha_small_body(self):
        body = (
            '<html><body><a href="/ref=cs_503_link">'
            "Continue shopping</a> on Amazon.com"
            "</body></html>"
        )
        assert detect_challenge(200, {}, body) == ChallengeType.AMAZON

    def test_amazon_amzn_marker(self):
        body = '<html><body>Continue Shopping on amzn.com store</body></html>'
        assert detect_challenge(200, {}, body) == ChallengeType.AMAZON

    def test_amazon_validate_captcha(self):
        body = (
            '<html><form action="/errors/validateCaptcha">'
            "Continue shopping</form></html>"
        )
        assert detect_challenge(200, {}, body) == ChallengeType.AMAZON

    def test_amazon_large_body_not_challenge(self):
        """Real Amazon product pages are huge, not challenges."""
        body = "Continue shopping on Amazon.com " + "x" * 60_000
        assert detect_challenge(200, {}, body) is None

    def test_amazon_no_continue_shopping(self):
        """Small Amazon-like page without 'continue shopping' is not a challenge."""
        body = '<html><body>Amazon.com product page</body></html>'
        assert detect_challenge(200, {}, body) is None

    def test_amazon_continue_shopping_non_amazon(self):
        """'Continue shopping' on non-Amazon page is not an Amazon challenge."""
        body = '<html><body>Continue shopping at MyStore</body></html>'
        assert detect_challenge(200, {}, body) is None


# ---------------------------------------------------------------------------
# Arkose Labs (FunCaptcha)
# ---------------------------------------------------------------------------


class TestArkose:
    def test_arkoselabs_script_403(self):
        """Arkose SDK script on 403 block page."""
        body = '<script src="//client-api.arkoselabs.com/v2/AAAA-BBBB/api.js"></script>'
        assert detect_challenge(403, {}, body) == ChallengeType.ARKOSE

    def test_funcaptcha_body_marker_403(self):
        """Legacy FunCaptcha name on 403."""
        body = '<div id="funcaptcha-container">Verify you are human</div>'
        assert detect_challenge(403, {}, body) == ChallengeType.ARKOSE

    def test_arkoselabs_on_200_login_page(self):
        """Arkose enforcement widget embedded in a normal 200 login page."""
        body = (
            '<html><head><script src="//company-api.arkoselabs.com/v2/'
            '9F35E182-C93C-EBCC-A31D-CF8ED317B996/api.js"'
            ' data-callback="setupEnforcement"></script></head>'
            '<body><form>Login</form></body></html>'
        )
        assert detect_challenge(200, {}, body) == ChallengeType.ARKOSE

    def test_funcaptcha_on_200(self):
        """FunCaptcha marker on 200 page."""
        body = '<div id="FunCaptcha">Solve the puzzle</div>'
        assert detect_challenge(200, {}, body) == ChallengeType.ARKOSE

    def test_arkoselabs_large_page_not_detected(self):
        """Large 200 page with arkoselabs is real content, not a challenge."""
        body = 'arkoselabs.com mentioned in article ' + 'x' * 120_000
        assert detect_challenge(200, {}, body) is None

    def test_arkoselabs_on_429(self):
        """Arkose on 429 rate limit."""
        body = '<script src="//client-api.arkoselabs.com/v2/KEY/api.js"></script>'
        assert detect_challenge(429, {}, body) == ChallengeType.ARKOSE


# ---------------------------------------------------------------------------
# hCaptcha
# ---------------------------------------------------------------------------


class TestHCaptcha:
    def test_hcaptcha_403_detected(self):
        """403 + hcaptcha.com body → HCAPTCHA."""
        body = '<script src="https://hcaptcha.com/1/api.js"></script>'
        assert detect_challenge(403, {}, body) == ChallengeType.HCAPTCHA

    def test_hcaptcha_429_h_captcha(self):
        """429 + h-captcha class → HCAPTCHA."""
        body = '<div class="h-captcha" data-sitekey="abc"></div>'
        assert detect_challenge(429, {}, body) == ChallengeType.HCAPTCHA

    def test_hcaptcha_200_small_body_detected(self):
        """200 + small body + hcaptcha.com/1/api.js → HCAPTCHA."""
        body = (
            '<html><head><script src="https://hcaptcha.com/1/api.js">'
            '</script></head><body>Verify</body></html>'
        )
        assert detect_challenge(200, {}, body) == ChallengeType.HCAPTCHA

    def test_hcaptcha_200_widget_id(self):
        """200 + data-hcaptcha-widget-id → HCAPTCHA."""
        body = '<div data-hcaptcha-widget-id="abc">Verify</div>'
        assert detect_challenge(200, {}, body) == ChallengeType.HCAPTCHA

    def test_hcaptcha_200_large_body_not_detected(self):
        """200 + >100KB body + hcaptcha markers → None (normal page)."""
        body = 'hcaptcha.com/1/api.js ' + 'x' * 120_000
        assert detect_challenge(200, {}, body) is None

    def test_hcaptcha_in_js_only_challenges(self):
        from wafer._challenge import JS_ONLY_CHALLENGES
        assert ChallengeType.HCAPTCHA in JS_ONLY_CHALLENGES


# ---------------------------------------------------------------------------
# reCAPTCHA
# ---------------------------------------------------------------------------


class TestReCaptcha:
    def test_recaptcha_403_detected(self):
        """403 + g-recaptcha body → RECAPTCHA."""
        body = '<div class="g-recaptcha" data-sitekey="abc"></div>'
        assert detect_challenge(403, {}, body) == ChallengeType.RECAPTCHA

    def test_recaptcha_403_google_url(self):
        """403 + google.com/recaptcha script → RECAPTCHA."""
        body = '<script src="https://www.google.com/recaptcha/api.js"></script>'
        assert detect_challenge(403, {}, body) == ChallengeType.RECAPTCHA

    def test_recaptcha_200_small_body_detected(self):
        """200 + small body + google.com/recaptcha → RECAPTCHA."""
        body = (
            '<html><head><script src="https://www.google.com/recaptcha/'
            'api.js"></script></head><body>Verify</body></html>'
        )
        assert detect_challenge(200, {}, body) == ChallengeType.RECAPTCHA

    def test_recaptcha_200_g_recaptcha_div(self):
        """200 + g-recaptcha div → RECAPTCHA."""
        body = '<div class="g-recaptcha" data-sitekey="abc">Solve</div>'
        assert detect_challenge(200, {}, body) == ChallengeType.RECAPTCHA

    def test_recaptcha_200_large_body_not_detected(self):
        """200 + >100KB body → None."""
        body = 'google.com/recaptcha g-recaptcha ' + 'x' * 120_000
        assert detect_challenge(200, {}, body) is None

    def test_recaptcha_in_js_only_challenges(self):
        from wafer._challenge import JS_ONLY_CHALLENGES
        assert ChallengeType.RECAPTCHA in JS_ONLY_CHALLENGES


# ---------------------------------------------------------------------------
# Generic JS Challenge
# ---------------------------------------------------------------------------


class TestGenericJS:
    def test_403_with_script_small_body(self):
        body = '<html><head><script>document.cookie="test=1";</script></head></html>'
        assert detect_challenge(403, {}, body) == ChallengeType.GENERIC_JS

    def test_429_with_script_small_body(self):
        body = '<html><head><script src="/challenge.js"></script></head></html>'
        assert detect_challenge(429, {}, body) == ChallengeType.GENERIC_JS

    def test_403_large_body_not_generic(self):
        """Large 403 pages are real error pages, not JS challenges."""
        body = (
            "<html><head><script>analytics();</script></head>"
            + "x" * 60_000
            + "</html>"
        )
        assert detect_challenge(403, {}, body) is None

    def test_403_no_script_not_generic(self):
        """403 without script tag is a normal error page."""
        body = '<html><body>Access Denied</body></html>'
        assert detect_challenge(403, {}, body) is None


# ---------------------------------------------------------------------------
# Negative cases: normal responses not misclassified
# ---------------------------------------------------------------------------


class TestNegativeCases:
    def test_200_empty_body(self):
        assert detect_challenge(200, {}, "") is None

    def test_200_normal_html(self):
        body = (
            "<html><head><title>My Page</title></head>"
            "<body>Hello world</body></html>"
        )
        assert detect_challenge(200, {}, body) is None

    def test_200_with_script_not_challenge(self):
        """Normal 200 page with scripts is not a challenge."""
        body = (
            '<html><head><script src="/app.js"></script>'
            "</head><body>Real content</body></html>"
        )
        assert detect_challenge(200, {}, body) is None

    def test_404_not_challenge(self):
        body = '<html><body>Page not found</body></html>'
        assert detect_challenge(404, {}, body) is None

    def test_500_not_challenge(self):
        body = '<html><body>Internal server error</body></html>'
        assert detect_challenge(500, {}, body) is None

    def test_403_plain_text_access_denied(self):
        """Plain 'access denied' without WAF markers is not classified."""
        body = '<html><body><h1>403 Forbidden</h1><p>Access denied.</p></body></html>'
        assert detect_challenge(403, {}, body) is None

    def test_301_redirect_not_challenge(self):
        headers = {"location": "https://example.com/new"}
        assert detect_challenge(301, headers, "") is None

    def test_200_large_page_with_amazon_text(self):
        """Large page should not be detected as challenge."""
        body = (
            "<html><body>Amazon.com: Great Product"
            " - Continue shopping for more</body>"
            + "x" * 100_000
            + "</html>"
        )
        assert detect_challenge(200, {}, body) is None

    def test_200_with_cf_ray_header_no_challenge(self):
        """cf-ray header alone (without cf-mitigated) is not a challenge."""
        headers = {"cf-ray": "abc123"}
        assert detect_challenge(200, headers, "Normal content") is None

    def test_cookie_name_substring_not_false_positive(self):
        """Cookie names that contain WAF names as substrings should not match."""
        # 'my_abck_token' contains '_abck' but is not an Akamai cookie
        headers = _h(set_cookie="my_abck_token=abc; Path=/")
        assert detect_challenge(403, headers, "") is None

    def test_px_cookie_value_not_false_positive(self):
        """WAF name in cookie value (not name) should not match."""
        headers = _h(set_cookie="session=contains_px3_data; Path=/")
        assert detect_challenge(403, headers, "") is None


# ---------------------------------------------------------------------------
# Priority / ordering tests
# ---------------------------------------------------------------------------


class TestDetectionPriority:
    def test_cf_mitigated_takes_priority_over_body(self):
        """Header-based CF detection should fire before any body checks."""
        headers = {"cf-mitigated": "challenge", "set-cookie": "datadome=x; Path=/"}
        body = '<script>datadome</script>'
        assert detect_challenge(403, headers, body) == ChallengeType.CLOUDFLARE

    def test_acw_before_generic_js(self):
        """ACW detection should fire before generic JS fallback."""
        body = "<script>var arg1='abc'; acw_sc__v2('test');</script>"
        assert detect_challenge(403, {}, body) == ChallengeType.ACW

    def test_specific_waf_before_generic(self):
        """Specific WAF detection should fire before generic JS."""
        headers = _h(set_cookie="datadome=abc; Path=/")
        body = '<script>datadome challenge</script>'
        assert detect_challenge(403, headers, body) == ChallengeType.DATADOME
