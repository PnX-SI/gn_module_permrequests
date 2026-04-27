import { Component, Input, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import {
  AbstractControl,
  ControlContainer,
  FormGroupDirective,
  ReactiveFormsModule,
} from '@angular/forms';
import { ConfigService } from '@geonature/services/config.service';

type TermsLink = {
  href: string;
};

@Component({
  standalone: true,
  selector: 'acknowledgement',
  templateUrl: './acknowledgement.component.html',
  styleUrls: ['./acknowledgement.component.scss'],
  imports: [CommonModule, ReactiveFormsModule],
  viewProviders: [{ provide: ControlContainer, useExisting: FormGroupDirective }],
})
export class AcknowledgementComponent {
  @Input() controlName = '';
  termsLink: TermsLink | null = null;
  readonly defaultTermsText = "conditions d'utilisations";

  constructor(
    private controlContainer: ControlContainer,
    private _configService: ConfigService
  ) {
    const moduleConfig = this._configService.PERMREQUESTS ?? {};
    this.termsLink = this._buildTermsLink(moduleConfig.TERMS_ACKNOWLEDGEMENT ?? null);
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
