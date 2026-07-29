import { Component, Inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { MatDialogModule, MAT_DIALOG_DATA, MatDialogRef } from '@angular/material/dialog';
import { MatButtonModule } from '@angular/material/button';
import { MatInputModule } from '@angular/material/input';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatButtonToggleModule } from '@angular/material/button-toggle';

import { TranslateModule, TranslateService } from '@ngx-translate/core';

import { I18nService } from '@geonature/shared/translate/i18n-service';

import { STATUS, STATUS_COLORS } from '../../models/status';

export interface ValidationDescriptionDialogData {
  validation_description: string | null;
  created_on: string | null;
  expiration_date: string | null;
  status: STATUS | null;
}

export interface ValidationDescriptionDialogResult {
  validated: boolean | null;
  validation_description: string | null;
  reset?: boolean;
}

type ValidationChoice = 'approve' | 'reject' | 'in_progress' | null;

@Component({
  standalone: true,
  selector: 'permission-request-validation-description-dialog',
  template: `
    <div class="card">
      <div class="card-header">
        <h1 mat-dialog-title>{{ 'Permrequests.ValidationDialog.Title' | translate }}</h1>
      </div>

      <div class="card-body">
        <div mat-dialog-content>
          <h2 class="ValidationDescriptionDialog__intro h4">
            {{ 'Permrequests.ValidationDialog.Status.Title' | translate }}
          </h2>
          <mat-button-toggle-group
            class="ValidationDescriptionDialog__toggle"
            [(ngModel)]="choice"
            name="validation-choice"
            aria-label="Choix de validation"
          >
            <mat-button-toggle
              class="DecisionToggle DecisionToggle--approve"
              [ngStyle]="decisionStyles.approve"
              [value]="'approve'"
            >
              {{ 'Permrequests.ValidationDialog.Status.Approve' | translate }}
            </mat-button-toggle>
            <mat-button-toggle
              class="DecisionToggle DecisionToggle--in-progress"
              [ngStyle]="decisionStyles.inProgress"
              [value]="'in_progress'"
            >
              {{ 'Permrequests.ValidationDialog.Status.InProgress' | translate }}
            </mat-button-toggle>
            <mat-button-toggle
              class="DecisionToggle DecisionToggle--reject"
              [ngStyle]="decisionStyles.reject"
              [value]="'reject'"
            >
              {{ 'Permrequests.ValidationDialog.Status.Refuse' | translate }}
            </mat-button-toggle>
          </mat-button-toggle-group>
          <div class="ValidationDescriptionDialog__status-hint-wrapper">
            <p
              *ngIf="choice === 'approve' && dateStatus"
              class="ValidationDescriptionDialog__status-hint"
              [ngStyle]="{ color: dateStatusColor }"
            >
              {{
                'Permrequests.ValidationDialog.Status.ApprovedHint'
                  | translate
                    : { date_status_label: ('Permrequests.Enums.Status.' + dateStatus | translate) }
              }}
            </p>
          </div>

          <h2 class="h4">
            {{ 'Permrequests.ValidationDialog.Message.Title' | translate }}
          </h2>
          <mat-form-field
            appearance="fill"
            class="ValidationDescriptionDialog__field"
          >
            <mat-label>{{ 'Permrequests.ValidationDialog.Message.Label' | translate }}</mat-label>
            <textarea
              matInput
              rows="6"
              [(ngModel)]="description"
              placeholder="{{ 'Permrequests.ValidationDialog.Message.Placeholder' | translate }}"
            ></textarea>
          </mat-form-field>
        </div>
      </div>

      <div class="card-footer">
        <div
          mat-dialog-actions
          class="ValidationDescriptionDialog__actions"
        >
          <div class="ValidationDescriptionDialog__actions-group">
            <button
              mat-stroked-button
              color="primary"
              type="button"
              (click)="onReset()"
              [disabled]="!canReset"
            >
              {{ 'Permrequests.ValidationDialog.Actions.Reset' | translate }}
            </button>
          </div>
          <div class="ValidationDescriptionDialog__actions-group">
            <button
              mat-button
              type="button"
              (click)="onCancel()"
            >
              {{ 'Permrequests.ValidationDialog.Actions.Cancel' | translate }}
            </button>
            <button
              mat-flat-button
              color="primary"
              type="button"
              (click)="onConfirm()"
              [disabled]="!choice"
            >
              {{ 'Permrequests.ValidationDialog.Actions.Validate' | translate }}
            </button>
          </div>
        </div>
      </div>
    </div>
  `,
  styles: [
    `
      .ValidationDescriptionDialog__field {
        width: 100%;
      }
      .ValidationDescriptionDialog__toggle {
        margin: 0.5rem 0 1rem;
        width: 100%;
      }
      .ValidationDescriptionDialog__intro {
        margin-bottom: 0.25rem;
      }
      .ValidationDescriptionDialog__status-hint-wrapper {
        min-height: 1.5rem;
        margin: 0 0 0.75rem;
        display: flex;
        align-items: flex-start;
      }
      .ValidationDescriptionDialog__status-hint {
        margin: 0;
        font-style: italic;
        color: #555;
        white-space: prewrap;
      }
      .ValidationDescriptionDialog__actions {
        display: flex;
        justify-content: space-between;
        align-items: center;
        gap: 0.5rem;
      }
      .ValidationDescriptionDialog__actions-group {
        display: flex;
        align-items: center;
        gap: 0.5rem;
      }
      .DecisionToggle {
        border: 1px solid transparent;
        --decision-color: #555;
        color: var(--decision-color);
        width: 100%;
      }
      .DecisionToggle.mat-button-toggle-checked {
        background-color: color-mix(in srgb, var(--decision-color) 12%, white);
        border-color: color-mix(in srgb, var(--decision-color) 45%, transparent);
        color: color-mix(in srgb, var(--decision-color) 80%, black);
      }
    `,
  ],
  imports: [
    CommonModule,
    FormsModule,
    MatDialogModule,
    MatButtonModule,
    MatInputModule,
    MatFormFieldModule,
    MatButtonToggleModule,
    TranslateModule,
  ],
})
export class ValidationDescriptionDialogComponent {
  description: string;
  choice: ValidationChoice;
  readonly canReset: boolean;
  readonly dateStatus: STATUS | null;
  readonly dateStatusColor: string | null;
  readonly decisionStyles = {
    approve: { '--decision-color': STATUS_COLORS[STATUS.ACTIVE] },
    reject: { '--decision-color': STATUS_COLORS[STATUS.REFUSED] },
    inProgress: { '--decision-color': STATUS_COLORS[STATUS.IN_PROGRESS] },
  };
  constructor(
    private _i18nService: I18nService,
    private _translateService: TranslateService,
    @Inject(MAT_DIALOG_DATA) public data: ValidationDescriptionDialogData,
    private _dialogRef: MatDialogRef<
      ValidationDescriptionDialogComponent,
      ValidationDescriptionDialogResult | undefined
    >
  ) {
    this._i18nService.initializeModuleTranslateService(this._translateService);
    this.description = data?.validation_description ?? '';
    this.choice = this._computeInitialChoice(data);
    this.canReset = this._computeCanReset(data);
    this.dateStatus = this._computeDateStatus(data?.created_on, data?.expiration_date);
    this.dateStatusColor = this.dateStatus ? STATUS_COLORS[this.dateStatus] : null;
  }

  onConfirm(): void {
    const trimmed = (this.description || '').trim();
    if (!this.choice) {
      this._dialogRef.close(undefined);
      return;
    }
    this._dialogRef.close({
      validated: this._choiceToValidated(this.choice),
      validation_description: trimmed.length ? trimmed : null,
      reset: false,
    });
  }

  onCancel(): void {
    this._dialogRef.close(undefined);
  }

  onReset(): void {
    if (!this.canReset) {
      return;
    }
    this._dialogRef.close({
      validated: null,
      validation_description: null,
      reset: true,
    });
  }

  private _computeDateStatus(
    created_on: string | null,
    expiration_date: string | null
  ): STATUS | null {
    if (!created_on && !expiration_date) {
      return null;
    }
    const now = new Date();
    const init = created_on ? new Date(created_on) : null;
    const exp = expiration_date ? new Date(expiration_date) : null;

    if (exp && !isNaN(exp.valueOf()) && exp < now) {
      return STATUS.EXPIRED;
    }
    if (init && !isNaN(init.valueOf()) && init > now) {
      return STATUS.UPCOMING;
    }
    return STATUS.ACTIVE;
  }

  private _choiceToValidated(choice: ValidationChoice): boolean | null {
    if (choice === 'approve') {
      return true;
    }
    if (choice === 'reject') {
      return false;
    }
    return null;
  }

  private _computeInitialChoice(data: ValidationDescriptionDialogData): ValidationChoice {
    if (!data) {
      return null;
    }
    if (data.status === STATUS.REFUSED) {
      return 'reject';
    }
    if (data.status === STATUS.IN_PROGRESS) {
      return 'in_progress';
    }
    if (
      data.status === STATUS.ACTIVE ||
      data.status === STATUS.UPCOMING ||
      data.status === STATUS.EXPIRED
    ) {
      return 'approve';
    }
    return null;
  }

  private _computeCanReset(data: ValidationDescriptionDialogData): boolean {
    const hasDecision =
      data?.status === STATUS.REFUSED ||
      data?.status === STATUS.ACTIVE ||
      data?.status === STATUS.UPCOMING ||
      data?.status === STATUS.IN_PROGRESS ||
      data?.status === STATUS.EXPIRED;
    return hasDecision;
  }
}
