import React from 'react';
import {
  Upload,
  ArrowRight,
  FileCode2,
  Activity,
  type LucideIcon,
} from 'lucide-react';
import { Modal } from './ui';

export const GUIDE_STORAGE_KEY = 'npv_welcome_v2';

interface GuideStep {
  icon: LucideIcon;
  title: string;
  body: React.ReactNode;
}

export const GUIDE_STEPS: GuideStep[] = [
  {
    icon: Upload,
    title: '۱. بارگذاری فایل یا الصاق لینک‌ها',
    body: (
      <>
        فایل‌های <code className="mono">.npvs</code> یا <code className="mono">.npvt</code> را در کادر ورودی رها فرموده یا
        لینک‌های مستقیم <code className="mono">vless/vmess/trojan/ss</code> را الصاق نمایید. در صورت نیاز به رمز عبور، فیلد مربوطه تکمیل می‌گردد.
      </>
    ),
  },
  {
    icon: FileCode2,
    title: '۲. انتخاب و دریافت قالب خروجی',
    body: (
      <>
        فرآیند رمزگشایی بی‌درنگ و کلاینت‌ساید انجام می‌شود. شما می‌توانید از میان قالب‌های لینک خام، Base64،{' '}
        <b>Xray JSON</b>، <b>Sing-box</b> یا <b>Clash Meta</b> خروجی موردنظر را رونویسی یا بارگیری نمایید.
      </>
    ),
  },
  {
    icon: Activity,
    title: '۳. سنجش پینگ سرورها و دریافت بارکد QR',
    body: (
      <>
        مشخصات فنی و وضعیت اتصال هر سرور را بررسی فرموده یا جهت انتقال مستقیم به تلفن همراه، بارکد <b>QR</b> اختصاصی آن
        را اسکن نمایید. در صورت بروز اختلال در گواهی‌های Fastly، سیستم تثبیت خودکار فعال خواهد بود.
      </>
    ),
  },
  {
    icon: ArrowRight,
    title: '۴. شخصی‌سازی در استودیوی اختصاصی',
    body: (
      <>
        از طریق تب <b>استودیو</b> می‌توانید عناوین سرورها، الگوهای شماره‌گذاری و کپشن انتشار را با هویت اختصاصی خود بازنویسی نموده
        و کانتینر جدید <code className="mono">.npvs</code> تولید فرمایید.
      </>
    ),
  },
];

export const GuideSteps: React.FC = () => (
  <ol className="guide-steps">
    {GUIDE_STEPS.map((s, i) => {
      const Icon = s.icon;
      return (
        <li className="guide-step" key={i}>
          <span className="guide-step__num">{i + 1}</span>
          <div className="guide-step__body">
            <span className="guide-step__title">
              <Icon style={{ width: 14, height: 14 }} />
              {s.title}
            </span>
            <p className="guide-step__text">{s.body}</p>
          </div>
        </li>
      );
    })}
  </ol>
);

export const WelcomeModal: React.FC<{
  open: boolean;
  onClose: () => void;
  onGoToDecode?: () => void;
}> = ({ open, onClose, onGoToDecode }) => (
  <Modal
    open={open}
    onClose={onClose}
    title="راهنمای جامع کارکرد سامانه"
    subtitle="چهار گام ساده جهت تبدیل و استفاده از کانفیگ‌های ارتباطی — پردازش ۱۰۰٪ آفلاین"
    footer={
      <div className="flex flex-wrap items-center justify-between gap-3">
        <span style={{ fontSize: 11.5, color: 'var(--faint)' }}>امنیت کامل داده‌ها · بدون ارسال اطلاعات به سرور</span>
        <div className="flex items-center gap-2">
          <button type="button" onClick={onClose} className="btn btn--ghost btn--sm">
            بستن
          </button>
          {onGoToDecode && (
            <button
              type="button"
              onClick={() => {
                onGoToDecode();
                onClose();
              }}
              className="btn btn--primary btn--sm"
            >
              شروع فرآیند تبدیل
            </button>
          )}
        </div>
      </div>
    }
  >
    <p className="guide-intro">
      سامانه <b>NPV//FORGE</b> ابزاری تخصصی جهت رمزگشایی کانتینرهای قفل‌شده NPV Tunnel و تبدیل مستقیم آن‌ها به ساختارهای
      استاندارد V2Ray، Xray، Sing-box و Clash Meta بدون واسطه سرور می‌باشد.
    </p>
    <GuideSteps />
  </Modal>
);
