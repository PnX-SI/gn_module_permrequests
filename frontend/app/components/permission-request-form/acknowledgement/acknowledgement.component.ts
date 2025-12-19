import { Component, Input } from '@angular/core';
import { CommonModule } from '@angular/common';
import {
  AbstractControl,
  ControlContainer,
  FormGroupDirective,
  ReactiveFormsModule,
} from '@angular/forms';

@Component({
  standalone: true,
  selector: 'acknowledgement',
  templateUrl: './acknowledgement.component.html',
  styleUrls: ['./acknowledgement.component.scss'],
  imports: [CommonModule, ReactiveFormsModule],
  viewProviders: [{ provide: ControlContainer, useExisting: FormGroupDirective }],
})
export class AcknowledgementComponent {
  @Input() shouldDisplayAcknowledgement = false;
  @Input() formControlName = '';

  constructor(private controlContainer: ControlContainer) {}

  get acknowledgeTermsControl(): AbstractControl | null {
    if (!this.formControlName) {
      return null;
    }
    return this.controlContainer?.control?.get(this.formControlName) ?? null;
  }
}
