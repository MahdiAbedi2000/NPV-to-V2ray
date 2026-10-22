/* ------------------------------------------------------------------ */
/*  Alias profile — the fixed identity the studio can wear              */
/*                                                                     */
/*  When the vault is open the whole shell can present itself with a   */
/*  constant name and caption instead of the product name. Everything   */
/*  is stored locally; nothing is uploaded.                            */
/* ------------------------------------------------------------------ */

export interface AliasProfile {
  /** master switch — the disguise only applies while the vault is open */
  enabled: boolean;
  /** constant visible name, e.g. "NODE//GRID" */
  name: string;
  /** constant visible caption / subtitle */
  caption: string;
  /** mono kicker shown under the name */
  kicker: string;
}

const STORAGE_KEY = 'npv_alias_profile_v1';

const DEFAULT_DESCRIPTION =
  'رمزگشایی و تبدیل دوطرفه کانفیگ‌های NPV Tunnel (NapsternetV .npvt / .npvs / NPVT1 / NPVO1 / NetMod) به لینک V2Ray، Xray JSON، Sing-box و Clash Meta — کاملاً آفلاین، بدون سرور.';

export const DEFAULT_ALIAS: AliasProfile = {
  enabled: false,
  name: 'NODE//GRID',
  caption: 'مجموعه کانفیگ اختصاصی و پایدار',
  kicker: 'PRIVATE DISTRIBUTION NODE',
};

export function loadAliasProfile(): AliasProfile {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return { ...DEFAULT_ALIAS };
    const parsed = JSON.parse(raw);
    return {
      enabled: Boolean(parsed?.enabled),
      name: typeof parsed?.name === 'string' ? parsed.name : DEFAULT_ALIAS.name,
      caption: typeof parsed?.caption === 'string' ? parsed.caption : DEFAULT_ALIAS.caption,
      kicker: typeof parsed?.kicker === 'string' ? parsed.kicker : DEFAULT_ALIAS.kicker,
    };
  } catch {
    return { ...DEFAULT_ALIAS };
  }
}

export function saveAliasProfile(profile: AliasProfile): void {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(profile));
  } catch {}
}

/** Apply the alias to the document head (title + meta description). */
export function applyDocumentIdentity(profile: AliasProfile, active: boolean): void {
  try {
    const use = active && profile.enabled && profile.name.trim();
    document.title = use
      ? `${profile.name.trim()} — ${profile.caption.trim()}`
      : 'NPV//FORGE — تبدیل‌کننده کانفیگ NPV Tunnel به V2Ray';
    const meta = document.querySelector('meta[name="description"]');
    if (meta) meta.setAttribute('content', use ? profile.caption.trim() : DEFAULT_DESCRIPTION);
  } catch {}
}
