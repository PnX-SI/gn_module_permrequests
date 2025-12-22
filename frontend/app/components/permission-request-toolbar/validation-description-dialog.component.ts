import { Component, Inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { MatDialogModule, MAT_DIALOG_DATA, MatDialogRef } from '@angular/material/dialog';
import { MatButtonModule } from '@angular/material/button';
import { MatInputModule } from '@angular/material/input';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatButtonToggleModule } from '@angular/material/button-toggle';
import { RouterModule, Params } from '@angular/router';
import { STATUS, STATUS_LABELS, STATUS_COLORS } from '../../models/status';

export interface ValidationDescriptionDialogData {
  validation_description: string | null;
  created_on: string | null;
  expiration_date: string | null;
  status: STATUS | null;
  cdNom: number[];
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
        <h1 mat-dialog-title>Valider la demande de permission</h1>
      </div>
      <div class="card-body">
        <div mat-dialog-content>
          <p class="ValidationDescriptionDialog__intro">Statut de validation</p>
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
              Valider
            </mat-button-toggle>
            <mat-button-toggle
              class="DecisionToggle DecisionToggle--in-progress"
              [ngStyle]="decisionStyles.inProgress"
              [value]="'in_progress'"
            >
              En cours
            </mat-button-toggle>
            <mat-button-toggle
              class="DecisionToggle DecisionToggle--reject"
              [ngStyle]="decisionStyles.reject"
              [value]="'reject'"
            >
              Refuser
            </mat-button-toggle>
          </mat-button-toggle-group>
          <div class="ValidationDescriptionDialog__status-hint-wrapper">
            <p
              *ngIf="choice === 'approve' && dateStatusLabel"
              class="ValidationDescriptionDialog__status-hint"
              [ngStyle]="{ color: dateStatusColor }"
            >
              Cette demande sera considérée comme "{{ dateStatusLabel }}".
            </p>
          </div>
          <p>Message à transmettre lors de cette validation</p>
          <mat-form-field
            appearance="fill"
            class="ValidationDescriptionDialog__field"
          >
            <mat-label>Message (optionnel)</mat-label>
            <textarea
              matInput
              rows="6"
              [(ngModel)]="description"
              placeholder="Renseignez un commentaire"
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
            <a
              mat-stroked-button
              color="primary"
              [routerLink]="syntheseLink"
              [queryParams]="syntheseQueryParams"
              target="_blank"
              rel="noopener"
            >
              Visualiser les données
            </a>
            <button
              mat-stroked-button
              color="primary"
              type="button"
              (click)="onReset()"
              [disabled]="!canReset"
            >
              Réinitialiser
            </button>
          </div>
          <div class="ValidationDescriptionDialog__actions-group">
            <button
              mat-button
              type="button"
              (click)="onCancel()"
            >
              Annuler
            </button>
            <button
              mat-flat-button
              color="primary"
              type="button"
              (click)="onConfirm()"
              [disabled]="!choice"
            >
              Valider
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
    RouterModule,
  ],
})
export class ValidationDescriptionDialogComponent {
  description: string;
  choice: ValidationChoice;
  readonly canReset: boolean;
  readonly dateStatus: STATUS | null;
  readonly dateStatusLabel: string | null;
  readonly dateStatusColor: string | null;
  readonly decisionStyles = {
    approve: { '--decision-color': STATUS_COLORS[STATUS.ACTIVE] },
    reject: { '--decision-color': STATUS_COLORS[STATUS.REFUSED] },
    inProgress: { '--decision-color': STATUS_COLORS[STATUS.IN_PROGRESS] },
  };
  readonly syntheseLink = ['/synthese'];
  readonly syntheseQueryParams: Params;

  constructor(
    @Inject(MAT_DIALOG_DATA) public data: ValidationDescriptionDialogData,
    private _dialogRef: MatDialogRef<
      ValidationDescriptionDialogComponent,
      ValidationDescriptionDialogResult | undefined
    >
  ) {
    this.description = data?.validation_description ?? '';
    this.choice = this._computeInitialChoice(data);
    this.canReset = this._computeCanReset(data);
    this.dateStatus = this._computeDateStatus(data?.created_on, data?.expiration_date);
    this.dateStatusLabel = this.dateStatus ? STATUS_LABELS[this.dateStatus] : null;
    this.dateStatusColor = this.dateStatus ? STATUS_COLORS[this.dateStatus] : null;
    this.syntheseQueryParams = this._computeSyntheseQueryParams(data?.cdNom ?? []);
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

  private _computeSyntheseQueryParams(cdNoms: number[]) {
    const query: Params = {};
    const uniqueCdNoms = Array.from(
      new Set(
        (cdNoms || [])
          .flatMap((value) => value)
          .map((value) => Number(value))
          .filter((value) => Number.isFinite(value))
      )
    ) as number[];
    if (uniqueCdNoms.length) {
      // In synthse, the query_params available is cd_ref.
      // In permission request, the taxon is referenced by cd_nom because of fk behavior.
      // But it's actually a cd_ref.
      query.cd_ref = uniqueCdNoms;
    }
    return query;
  }
}
