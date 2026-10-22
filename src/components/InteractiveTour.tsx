import React, { useState, useEffect } from 'react';
import {
  ArrowRight,
  ArrowLeft,
  X,
  Upload,
  FileCode2,
  Activity,
  FolderArchive,
  Wand2,
  CheckCircle2,
} from 'lucide-react';

export interface TourStep {
  targetId: string;
  title: string;
  description: string;
  icon: React.ComponentType<{ style?: React.CSSProperties; className?: string }>;
  hint: string;
}

export const TOUR_STEPS: TourStep[] = [
  {
    targetId: 'decode-studio',
    title: 'گام نخست: دریافت و بارگذاری کانفیگ',
    description:
      'فایل‌های رمزنگاری‌شده با پسوند .npvs یا .npvt و متن‌های رمزشده را در این کادر رها نموده یا لینک‌های اتصال vless، vmess، trojan و shadowsocks را الصاق فرمایید. در صورت وجود رمز عبور اختصاصی روی فایل، فیلد مربوطه به صورت خودکار فعال می‌گردد.',
    icon: Upload,
    hint: 'پشتیبانی کامل از کانتینرهای رمزنگاری‌شده نسل ۴ (AES-CTR)، نسل ۵ (White-Box) و NetMod',
  },
  {
    targetId: 'output-panel',
    title: 'گام دوم: انتخاب و دریافت قالب خروجی',
    description:
      'موتور پردازشی به محض دریافت ورودی، کلیه گره‌ها را رمزگشایی می‌نماید. شما می‌توانید قالب موردنظر خود را میان لینک‌های مستقیم، اشتراک Base64، ساختار Xray JSON، Sing-box و Clash Meta انتخاب نموده و به صورت یکجا رونویسی یا بارگیری فرمایید.',
    icon: FileCode2,
    hint: 'مجهز به سیستم تثبیت خودکار گواهی‌های TLS سرورهای شبکه Fastly',
  },
  {
    targetId: 'nodes',
    title: 'گام سوم: مدیریت سرورها، سنجش پینگ و بارکد QR',
    description:
      'تمامی سرورهای موجود در کانفیگ به همراه مشخصات فنی، پروتکل و پورت به تفکیک نمایش داده می‌شوند. شما می‌توانید پینگ اتصال هر سرور را به صورت زنده ارزیابی نموده و جهت راه‌اندازی سریع در تلفن همراه، بارکد QR اختصاصی آن را اسکن فرمایید.',
    icon: Activity,
    hint: 'امکان جستجوی هوشمند بر اساس عنوان، آدرس IP و نوع پروتکل ارتباطی',
  },
  {
    targetId: 'library-space',
    title: 'گام چهارم: آرشیو و ادغام دسته‌ای کانفیگ‌ها',
    description:
      'شما می‌توانید سرورهای استخراج‌شده از هر فایل را در مجموعه محلی ذخیره نموده و بلافاصله فایل‌های بعدی را جهت پردازش وارد فرمایید. در پایان، امکان رونویسی و بارگیری یکپارچه کلیه سرورهای بسته‌های مختلف در یک فایل واحد میسر می‌باشد.',
    icon: FolderArchive,
    hint: 'داده‌ها به صورت امن در حافظه محلی مرورگر ذخیره شده و پس از بازخوانی صفحه نیز پایدار خواهند بود.',
  },
  {
    targetId: 'top',
    title: 'گام پنجم: استودیوی اختصاصی بازنویسی و انتشار',
    description:
      'از طریق منوی اصلی به بخش استودیو مراجعه فرمایید تا بتوانید عناوین سرورها، پیشوندها، اطلاعات تماس و کپشن انتشار را با هویت برند خود بازنویسی نموده و کانتینرهای رمزنگاری‌شده جدید با امضای اختصاصی تولید نمایید.',
    icon: Wand2,
    hint: 'ورود به این بخش با رمز عبور مدیریتی محافظت می‌گردد.',
  },
];

interface InteractiveTourProps {
  open: boolean;
  onClose: () => void;
  onSwitchMode?: (mode: 'decode' | 'forge' | 'vault') => void;
}

export const InteractiveTour: React.FC<InteractiveTourProps> = ({
  open,
  onClose,
  onSwitchMode,
}) => {
  const [currentStepIndex, setCurrentStepIndex] = useState(0);

  const step = TOUR_STEPS[currentStepIndex];

  useEffect(() => {
    if (!open) {
      document.querySelectorAll('.tour-highlight-active').forEach((el) => {
        el.classList.remove('tour-highlight-active');
      });
      return;
    }

    if (step.targetId === 'top') {
      window.scrollTo({ top: 0, behavior: 'smooth' });
    } else {
      const el = document.getElementById(step.targetId);
      if (el) {
        document.querySelectorAll('.tour-highlight-active').forEach((other) => {
          other.classList.remove('tour-highlight-active');
        });
        el.classList.add('tour-highlight-active');
        el.scrollIntoView({ behavior: 'smooth', block: 'center' });
      }
    }

    return () => {
      document.querySelectorAll('.tour-highlight-active').forEach((el) => {
        el.classList.remove('tour-highlight-active');
      });
    };
  }, [open, currentStepIndex, step]);

  useEffect(() => {
    if (!open) return;
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
      else if (e.key === 'ArrowLeft') handleNext();
      else if (e.key === 'ArrowRight') handlePrev();
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [open, currentStepIndex]);

  const handleNext = () => {
    if (currentStepIndex < TOUR_STEPS.length - 1) {
      setCurrentStepIndex((prev) => prev + 1);
    } else {
      onClose();
    }
  };

  const handlePrev = () => {
    if (currentStepIndex > 0) {
      setCurrentStepIndex((prev) => prev - 1);
    }
  };

  if (!open) return null;

  const Icon = step.icon;
  const isFirst = currentStepIndex === 0;
  const isLast = currentStepIndex === TOUR_STEPS.length - 1;

  return (
    <>
      <div className="tour-backdrop" onClick={onClose} aria-hidden="true" />

      <div className="tour-floating-card" role="dialog" aria-modal="true" aria-label="راهنمای تعاملی سامانه">
        <div className="tour-floating-card__progress">
          {TOUR_STEPS.map((_, i) => (
            <span
              key={i}
              className={`tour-progress-dot ${i === currentStepIndex ? 'is-active' : ''} ${
                i < currentStepIndex ? 'is-passed' : ''
              }`}
              onClick={() => setCurrentStepIndex(i)}
              title={`مرحله ${i + 1}`}
            />
          ))}
        </div>

        <div className="tour-floating-card__body">
          <div className="flex items-start justify-between gap-3">
            <div className="flex items-center gap-2.5">
              <div className="tour-step-icon">
                <Icon style={{ width: 17, height: 17 }} />
              </div>
              <div>
                <span className="mono text-[11px] text-[var(--accent)] font-semibold">
                  مرحله {(currentStepIndex + 1).toLocaleString('fa-IR')} از {TOUR_STEPS.length.toLocaleString('fa-IR')}
                </span>
                <h4 className="text-sm font-bold text-[var(--text)] m-0 leading-tight">
                  {step.title}
                </h4>
              </div>
            </div>

            <button
              type="button"
              onClick={onClose}
              className="btn btn--icon btn--ghost !w-7 !h-7"
              aria-label="بستن راهنما"
            >
              <X style={{ width: 14, height: 14 }} />
            </button>
          </div>

          <p className="tour-step-desc">{step.description}</p>

          <div className="tour-step-hint">
            <CheckCircle2 style={{ width: 13, height: 13, flex: 'none', color: 'var(--accent)' }} />
            <span>{step.hint}</span>
          </div>
        </div>

        <div className="tour-floating-card__foot">
          <button
            type="button"
            onClick={onClose}
            className="btn btn--ghost btn--sm !text-xs text-[var(--faint)]"
          >
            انصراف و خروج
          </button>

          <div className="flex items-center gap-2">
            {!isFirst && (
              <button
                type="button"
                onClick={handlePrev}
                className="btn btn--ghost btn--sm"
              >
                <ArrowRight style={{ width: 13, height: 13 }} />
                <span>گام پیشین</span>
              </button>
            )}

            <button
              type="button"
              onClick={handleNext}
              className="btn btn--primary btn--sm"
            >
              <span>{isLast ? 'تکمیل و شروع استفاده' : 'گام بعدی'}</span>
              {!isLast && <ArrowLeft style={{ width: 13, height: 13 }} />}
            </button>
          </div>
        </div>
      </div>
    </>
  );
};
