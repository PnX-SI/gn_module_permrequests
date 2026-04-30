import { Component, Input } from '@angular/core';
import { CommonModule } from '@angular/common';
import {
  AbstractControl,
  ControlContainer,
  FormGroupDirective,
  ReactiveFormsModule,
} from '@angular/forms';

import { TranslateModule, TranslateService } from '@ngx-translate/core';

import { ConfigService } from '@geonature/services/config.service';
import { I18nService } from '@geonature/shared/translate/i18n-service';


type TermsLink = {
  classCss: string;
  href: string;
  target: string;
  rel: string;
};


@Component({
  standalone: true,
  selector: 'acknowledgement',
  templateUrl: './acknowledgement.component.html',
  styleUrls: ['./acknowledgement.component.scss'],
  imports: [CommonModule, ReactiveFormsModule, TranslateModule],
  viewProviders: [{ provide: ControlContainer, useExisting: FormGroupDirective }],
})
export class AcknowledgementComponent {
  @Input() controlName = '';
  termsLink: TermsLink | null = null;

  constructor(
    private controlContainer: ControlContainer,
    private _configService: ConfigService,
    private _i18nService: I18nService,
    private _translateService: TranslateService,
  ) {
    const moduleConfig = this._configService.PERMREQUESTS ?? {};
    this.termsLink = this._buildTermsLink(moduleConfig.TERMS_ACKNOWLEDGEMENT ?? null);
    this._i18nService.initializeModuleTranslateService(this._translateService);
  }

  get acknowledgeTermsControl(): AbstractControl | null {
    if (!this.controlName) {
      return null;
    }
    return this.controlContainer?.control?.get(this.controlName) ?? null;
  }

  private _buildTermsLink(termsConfig: any): TermsLink | null {
    if (!termsConfig || typeof termsConfig !== 'object') {
      return null;
    }

    const url = this._normalizeConfigValue(termsConfig.URL);
    if (url) {
      return {
        href: url,
        classCss: termsConfig.CLASS_CSS || 'Acknowledgment__link',
        target: '_blank',
        rel: 'noopener',
      };
    }

    return null;
  }

  private _normalizeConfigValue(value: unknown): string | null {
    if (typeof value !== 'string') {
      return null;
    }
    const trimmed = value.trim();
    return trimmed ? trimmed : null;
  }
}
