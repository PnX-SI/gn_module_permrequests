import { Component, Inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { MatDialogModule, MAT_DIALOG_DATA, MatDialogRef } from '@angular/material/dialog';
import { MatButtonModule } from '@angular/material/button';
import { MatInputModule } from '@angular/material/input';
import { MatFormFieldModule } from '@angular/material/form-field';

export interface ValidationDescriptionDialogData {
  validated: boolean;
  validation_description: string | null;
}

@Component({
  standalone: true,
  selector: 'permission-request-validation-description-dialog',
  template: `
    <h1 mat-dialog-title>Commentaire de validation</h1>
    <div mat-dialog-content>
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
    `,
  ],
  imports: [
    CommonModule,
    FormsModule,
    MatDialogModule,
    MatButtonModule,
    MatInputModule,
    MatFormFieldModule,
  ],
})
export class ValidationDescriptionDialogComponent {
  description: string;

  constructor(
    @Inject(MAT_DIALOG_DATA) public data: ValidationDescriptionDialogData,
    private _dialogRef: MatDialogRef<ValidationDescriptionDialogComponent, string | null>
  ) {
    this.description = data?.validation_description ?? '';
  }

  onConfirm(): void {
    const trimmed = (this.description || '').trim();
    this._dialogRef.close(trimmed.length ? trimmed : null);
  }

  onCancel(): void {
    this._dialogRef.close(undefined);
  }
}
