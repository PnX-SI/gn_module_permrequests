import { Component, Inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { MatDialogModule, MAT_DIALOG_DATA, MatDialogRef } from '@angular/material/dialog';
import { MatButtonModule } from '@angular/material/button';
import { MatInputModule } from '@angular/material/input';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatButtonToggleModule } from '@angular/material/button-toggle';
import { STATUS, STATUS_LABELS, STATUS_COLORS } from '../../models/status';

export interface ValidationDescriptionDialogData {
  validated: boolean | null;
  validation_description: string | null;
  initialization_date: string | null;
  expiration_date: string | null;
}

export interface ValidationDescriptionDialogResult {
  validated: boolean | null;
  validation_description: string | null;
}

@Component({
  standalone: true,
  selector: 'permission-request-validation-description-dialog',
  template: `
    <h1 mat-dialog-title>Commentaire de validation</h1>
    <div mat-dialog-content>
      <p class="ValidationDescriptionDialog__intro">
        Choisissez le statut de validation puis ajoutez un message optionnel.
      </p>
      <mat-button-toggle-group
        class="ValidationDescriptionDialog__toggle"
        [(ngModel)]="validated"
        name="validated"
        aria-label="Choix de validation"
      >
        <mat-button-toggle
          class="DecisionToggle DecisionToggle--approve"
          [ngStyle]="decisionStyles.approve"
          [value]="true"
        >
          Valider
        </mat-button-toggle>
        <mat-button-toggle
          class="DecisionToggle DecisionToggle--reject"
          [ngStyle]="decisionStyles.reject"
          [value]="false"
        >
          Refuser
        </mat-button-toggle>
        <mat-button-toggle
          class="DecisionToggle DecisionToggle--pending"
          [ngStyle]="decisionStyles.pending"
          [value]="null"
        >
          Non traitée
        </mat-button-toggle>
      </mat-button-toggle-group>
      <p
        *ngIf="validated === true && dateStatusLabel"
        class="ValidationDescriptionDialog__status-hint"
        [ngStyle]="{ color: dateStatusColor }"
      >
        Cette demande sera considérée comme "{{ dateStatusLabel }}".
      </p>
      <p>
        Vous pouvez renseigner un message optionnel à transmettre lors de cette validation.
      </p>
      <mat-form-field appearance="fill" class="ValidationDescriptionDialog__field">
        <mat-label>Message (optionnel)</mat-label>
        <textarea
          matInput
          rows="3"
          [(ngModel)]="description"
          placeholder="Renseignez un commentaire"
        ></textarea>
      </mat-form-field>
    </div>
    <div mat-dialog-actions align="end">
      <button mat-button type="button" (click)="onCancel()">Annuler</button>
      <button mat-flat-button color="primary" type="button" (click)="onConfirm()">Valider</button>
    </div>
  `,
  styles: [
    `
      .ValidationDescriptionDialog__field {
        width: 100%;
      }
      .ValidationDescriptionDialog__toggle {
        margin: 0.5rem 0 1rem;
      }
      .ValidationDescriptionDialog__intro {
        margin-bottom: 0.25rem;
      }
      .ValidationDescriptionDialog__status-hint {
        margin: 0 0 0.75rem;
        font-style: italic;
        color: #555;
        white-space: prewrap;
      }
      .DecisionToggle {
        border: 1px solid transparent;
        --decision-color: #555;
        color: var(--decision-color);
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
  ],
})
export class ValidationDescriptionDialogComponent {
  description: string;
  validated: boolean | null;
  readonly dateStatus: STATUS | null;
  readonly dateStatusLabel: string | null;
  readonly dateStatusColor: string | null;
  readonly decisionStyles = {
    approve: { '--decision-color': STATUS_COLORS[STATUS.ACTIVE] },
    reject: { '--decision-color': STATUS_COLORS[STATUS.REFUSED] },
    pending: { '--decision-color': STATUS_COLORS[STATUS.PENDING] },
  };

  constructor(
    @Inject(MAT_DIALOG_DATA) public data: ValidationDescriptionDialogData,
    private _dialogRef: MatDialogRef<
      ValidationDescriptionDialogComponent,
      ValidationDescriptionDialogResult | undefined
    >
  ) {
    this.description = data?.validation_description ?? '';
    this.validated = data?.validated ?? null;
    this.dateStatus = this._computeDateStatus(data?.initialization_date, data?.expiration_date);
    this.dateStatusLabel = this.dateStatus ? STATUS_LABELS[this.dateStatus] : null;
    this.dateStatusColor = this.dateStatus ? STATUS_COLORS[this.dateStatus] : null;
  }

  onConfirm(): void {
    const trimmed = (this.description || '').trim();
    this._dialogRef.close({
      validated: this.validated,
      validation_description: trimmed.length ? trimmed : null,
    });
  }

  onCancel(): void {
    this._dialogRef.close(undefined);
  }

  private _computeDateStatus(
    initialization_date: string | null,
    expiration_date: string | null
  ): STATUS | null {
    if (!initialization_date && !expiration_date) {
      return null;
    }
    const now = new Date();
    const init = initialization_date ? new Date(initialization_date) : null;
    const exp = expiration_date ? new Date(expiration_date) : null;

    if (exp && !isNaN(exp.valueOf()) && exp < now) {
      return STATUS.EXPIRED;
    }
    if (init && !isNaN(init.valueOf()) && init > now) {
      return STATUS.UPCOMING;
    }
    return STATUS.ACTIVE;
  }
}
