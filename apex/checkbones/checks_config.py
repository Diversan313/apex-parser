"""Проверки конфига: ключевые флаги на месте и в рабочем состоянии."""
from apex import config as cfg


def check_pipeline_flags():
    assert cfg.AUTO_DOWNLOAD_XRAY is True
    assert cfg.ENABLE_TG_SOURCES in (True, False)
    assert cfg.DECRYPT_HAPP in (True, False)
    assert cfg.SECURE_SOURCES_GITHUB in (True, False)
    assert cfg.SPLIT_SOURCES in (True, False)
    assert cfg.SSL_VERIFY_SOURCES in (True, False)


def check_limits():
    assert 1 <= cfg.MAX_WORKERS <= 100
    assert cfg.MAX_CONFIGS_PER_IP_WL >= 1
    assert cfg.MAX_CONFIGS_PER_IP_BL >= 1
    assert cfg.MAX_CONFIGS_PER_SUBNET_BL >= 1
    assert cfg.MAX_CONFIGS_PER_EXIT_IP_BL >= 1
    assert cfg.MAX_CONFIGS_PER_EXIT_SUBNET_BL >= cfg.MAX_CONFIGS_PER_EXIT_IP_BL
    assert cfg.EXOTIC_MAX_NODES >= 1


def check_timeouts():
    assert cfg.XRAY_TEST_TIMEOUT > cfg.XRAY_START_TIMEOUT > 0
    assert cfg.TCP_CHECK_TIMEOUT > 0


def check_cf_subnets():
    # обе семьи подсетей должны собираться без ошибок и быть непустыми
    assert cfg.CF_NETWORKS and cfg.CF_IPV6_NETWORKS
